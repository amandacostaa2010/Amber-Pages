require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('Configure DATABASE_URL no arquivo .env');
  process.exit(1);
}
const app = express();
const db = new Pool({ connectionString: process.env.DATABASE_URL });
app.use(express.json({ limit: '12mb' }));
const PORT = process.env.PORT || 3000;

const defaults = { name: 'Leitor(a)', avatar: '', theme: 'ambar', phrase: 'Cada livro, um pedacinho de você.', featured: '', goal: 12, calm: false };
const validStatuses = new Set(['lido', 'lendo', 'quero', 'emprestado', 'releitura', 'abandonado']);
const validFormats = new Set(['fisico','ebook','audiobook']);
const validThemes = new Set(['ambar', 'luna', 'indigo', 'noite']);
const str = (v, max = 1000000) => String(v ?? '').slice(0, max);
const num = (v, max = 100000000) => Math.max(0, Math.min(max, Math.trunc(Number(v) || 0)));
const date = v => /^\d{4}-\d{2}-\d{2}$/.test(str(v)) ? str(v) : null;
const key = (v, fallback) => str(v || fallback, 100);

// A conta autenticada, nunca o primeiro usuário do banco, define a propriedade dos dados.
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const hashPassword = (password, salt) => crypto.scryptSync(password, salt, 64).toString('hex');
const authReady = (async () => {
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_auth (
    user_id BIGINT PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_sessions (
    token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await db.query('CREATE INDEX IF NOT EXISTS amber_sessions_user_idx ON public.amber_sessions(user_id)');
})();
authReady.catch(e => console.error('Falha ao preparar autenticação:', e));

async function requireAuth(req, res, next) {
  try {
    await authReady;
    const match = /^Bearer ([a-f0-9]{64})$/i.exec(req.headers.authorization || '');
    if (!match) return res.status(401).json({error:'Entre na sua conta para continuar.'});
    const result = await db.query(`SELECT s.user_id, a.email FROM public.amber_sessions s
      JOIN public.amber_auth a ON a.user_id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at>NOW()`, [sha256(match[1])]);
    if (!result.rows.length) return res.status(401).json({error:'Sessão expirada. Entre novamente.'});
    req.auth = {id:result.rows[0].user_id, email:result.rows[0].email, tokenHash:sha256(match[1])};
    next();
  } catch (e) { next(e); }
}

async function issueSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await db.query(`INSERT INTO public.amber_sessions(token_hash,user_id,expires_at)
    VALUES($1,$2,NOW()+INTERVAL '30 days')`, [sha256(token),userId]);
  return token;
}

app.post('/api/auth/register', async (req,res) => {
  const email=String(req.body?.email||'').trim().toLowerCase();
  const name=String(req.body?.name||'').trim().slice(0,120);
  const password=String(req.body?.password||'');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length>254 || !name || password.length<10 || password.length>128)
    return res.status(400).json({error:'Informe nome, e-mail válido e senha de 10 a 128 caracteres.'});
  let c;
  try {
    await authReady;
    c=await db.connect(); await c.query('BEGIN');
    // A conta legada só pode ser reivindicada pelo e-mail definido pelo operador.
    // Configure LEGACY_OWNER_EMAIL antes do primeiro cadastro, se houver dados antigos.
    let userId;
    if (process.env.LEGACY_OWNER_EMAIL?.trim().toLowerCase()===email) {
      const legacy=await c.query(`SELECT u.id FROM public.users u
        LEFT JOIN public.amber_auth a ON a.user_id=u.id
        WHERE a.user_id IS NULL ORDER BY u.id LIMIT 1 FOR UPDATE OF u`);
      if (legacy.rows.length) userId=legacy.rows[0].id;
    }
    if (!userId) {
      const created=await c.query('INSERT INTO public.users(name) VALUES($1) RETURNING id',[name]);
      userId=created.rows[0].id;
    }
    const salt=crypto.randomBytes(16).toString('hex');
    await c.query('INSERT INTO public.amber_auth(user_id,email,password_salt,password_hash) VALUES($1,$2,$3,$4)',
      [userId,email,salt,hashPassword(password,salt)]);
    await c.query('UPDATE public.users SET name=$2 WHERE id=$1',[userId,name]);
    await c.query('COMMIT');
    const token=await issueSession(userId);
    res.status(201).json({token,user:{id:String(userId),email,name}});
  } catch(e) {
    if(c) await c.query('ROLLBACK').catch(()=>{});
    res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'Este e-mail já está cadastrado.':'Não foi possível cadastrar.'});
  } finally {if(c)c.release();}
});

app.post('/api/auth/login', async(req,res)=>{
  try {
    await authReady;
    const email=String(req.body?.email||'').trim().toLowerCase();
    const password=String(req.body?.password||'');
    const r=await db.query(`SELECT a.*,u.name FROM public.amber_auth a
      JOIN public.users u ON u.id=a.user_id WHERE a.email=$1`,[email]);
    const account=r.rows[0];
    const expected=account?.password_hash || '0'.repeat(128);
    const actual=hashPassword(password,account?.password_salt || '0'.repeat(32));
    if(!account || !crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(expected,'hex')))
      return res.status(401).json({error:'E-mail ou senha incorretos.'});
    const token=await issueSession(account.user_id);
    res.json({token,user:{id:String(account.user_id),email,name:account.name}});
  } catch(e) {res.status(500).json({error:'Não foi possível entrar.'});}
});
app.get('/api/auth/me',requireAuth,async(req,res)=>{
  const r=await db.query('SELECT name FROM public.users WHERE id=$1',[req.auth.id]);
  res.json({user:{id:String(req.auth.id),email:req.auth.email,name:r.rows[0]?.name||''}});
});
app.post('/api/auth/logout',requireAuth,async(req,res)=>{
  await db.query('DELETE FROM public.amber_sessions WHERE token_hash=$1',[req.auth.tokenHash]);
  res.json({ok:true});
});

async function writeState(c, s, id) {
  const u = { ...defaults, ...(s.user || {}) };
  const books = s.books || [], clubs = s.clubs || [], logs = s.log || [];
  if (books.length > 5000 || clubs.length > 1000 || logs.length > 30000) throw Error('Limite de registros excedido.');
  const bookIds = new Set();
  for (const b of books) {
    const k = key(b.id, '');
    if (!k || bookIds.has(k)) throw Error('Livro com ID vazio ou duplicado.');
    bookIds.add(k);
  }
  const clubIds = new Set();
  for (const club of clubs) {
    const k = key(club.id, '');
    if (!k || clubIds.has(k)) throw Error('Clube com ID vazio ou duplicado.');
    clubIds.add(k);
  }
  await c.query("ALTER TABLE public.books ADD COLUMN IF NOT EXISTS reading_format TEXT NOT NULL DEFAULT 'fisico'");
  // Manter os IDs internos do HTML como app_key, usando IDs numéricos como PK no PostgreSQL.
  // Primeiro cria/atualiza livros, depois histórico e clubes; exclusões no fim.
  for (const b of books) {
    const vals = [id, key(b.id), str(b.title, 300), str(b.author, 200), num(b.pages), Math.min(num(b.read), num(b.pages) || 100000000), validStatuses.has(b.status) ? b.status : 'quero', Math.max(0, Math.min(5, Number(b.rating) || 0)), date(b.date), num(b.color, 7), str(b.colecao, 150), str(b.note), str(b.review), str(b.synopsis), str(b.lentTo, 160), date(b.lentDate), num(b.rereads), Boolean(b.rereading), b.cover ? str(b.cover) : null, validFormats.has(b.format) ? b.format : 'fisico'];
    await c.query(`INSERT INTO books (user_id,app_key,title,author,total_pages,current_page,status,rating,reading_date,cover_color,collection_name,quote,review,synopsis,lent_to,lent_date,rereads,is_rereading,cover,reading_format)
      VALUES (${vals.map((_,i)=>'$'+(i+1)).join(',')})
      ON CONFLICT (user_id,app_key) DO UPDATE SET
      title=EXCLUDED.title,author=EXCLUDED.author,total_pages=EXCLUDED.total_pages,current_page=EXCLUDED.current_page,status=EXCLUDED.status,rating=EXCLUDED.rating,reading_date=EXCLUDED.reading_date,cover_color=EXCLUDED.cover_color,collection_name=EXCLUDED.collection_name,quote=EXCLUDED.quote,review=EXCLUDED.review,synopsis=EXCLUDED.synopsis,lent_to=EXCLUDED.lent_to,lent_date=EXCLUDED.lent_date,rereads=EXCLUDED.rereads,is_rereading=EXCLUDED.is_rereading,cover=EXCLUDED.cover,reading_format=EXCLUDED.reading_format,updated_at=NOW()`, vals);
  }
  // Destaque deve ser atualizado antes da exclusão; a FK usa ON DELETE SET NULL.
  const featured = bookIds.has(str(u.featured)) ? str(u.featured) : null;
  await c.query(`UPDATE users SET name=$2,avatar=$3,theme=$4,phrase=$5,annual_goal=$6,calm_mode=$7,
    featured_book_id=(SELECT id FROM books WHERE user_id=$1 AND app_key=$8 LIMIT 1),updated_at=NOW() WHERE id=$1`,
    [id,str(u.name,120),u.avatar || null,validThemes.has(u.theme)?u.theme:'ambar',str(u.phrase),Math.max(1,num(u.goal,100000)),Boolean(u.calm),featured]);
  for (const club of clubs) {
    await c.query(`INSERT INTO book_clubs(user_id,app_key,name,monthly_book,page_goal,deadline)
      VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(user_id,app_key) DO UPDATE SET
      name=EXCLUDED.name,monthly_book=EXCLUDED.monthly_book,page_goal=EXCLUDED.page_goal,deadline=EXCLUDED.deadline,updated_at=NOW()`,
      [id,key(club.id),str(club.name,160),str(club.book,300),num(club.goal),date(club.end)]);
  }
  // Recria membros e logs como projeções do estado atual (transação única).
  await c.query(`DELETE FROM club_members WHERE club_id IN (SELECT id FROM book_clubs WHERE user_id=$1)`,[id]);
  for (const club of clubs) {
    const cr = await c.query('SELECT id FROM book_clubs WHERE user_id=$1 AND app_key=$2',[id,key(club.id)]);
    const names = new Set();
    for (const m of (club.members || [])) {
      const name = str(m.name,120);
      if (!name || names.has(name)) continue;
      names.add(name);
      await c.query('INSERT INTO club_members(club_id,name,pages_read) VALUES($1,$2,$3)',[cr.rows[0].id,name,num(m.pages)]);
    }
  }
  await c.query(`DELETE FROM reading_logs WHERE book_id IN (SELECT id FROM books WHERE user_id=$1)`,[id]);
  const logIds = new Set();
  for (const l of logs) {
    if (!bookIds.has(str(l.b))) continue;
    const lk = key(l.id, '');
    if (!lk || logIds.has(lk) || num(l.p) < 1) continue;
    logIds.add(lk);
    await c.query(`INSERT INTO reading_logs(book_id,app_key,reading_date,pages_read)
      SELECT id,$3,$4,$5 FROM books WHERE user_id=$1 AND app_key=$2`,
      [id,str(l.b),lk,date(l.d)||new Date().toISOString().slice(0,10),num(l.p)]);
  }
  await c.query(`DELETE FROM book_clubs WHERE user_id=$1 AND NOT (app_key=ANY($2::text[]))`,[id,[...clubIds]]);
  await c.query(`DELETE FROM books WHERE user_id=$1 AND NOT (app_key=ANY($2::text[]))`,[id,[...bookIds]]);
}

async function readState(c,id) {
  await c.query("ALTER TABLE public.books ADD COLUMN IF NOT EXISTS reading_format TEXT NOT NULL DEFAULT 'fisico'");
  const [u,b,cl,m,l] = [
    await c.query('SELECT * FROM users WHERE id=$1',[id]),
    await c.query(`SELECT app_key AS id,title,author,total_pages AS pages,current_page AS read,status,rating,reading_date AS date,cover_color AS color,collection_name AS colecao,quote AS note,review,synopsis,lent_to AS "lentTo",lent_date AS "lentDate",rereads,is_rereading AS rereading,cover,reading_format AS format FROM books WHERE user_id=$1 ORDER BY id`,[id]),
    await c.query('SELECT id,app_key,name,monthly_book,page_goal,deadline FROM book_clubs WHERE user_id=$1 ORDER BY id',[id]),
    await c.query('SELECT cm.club_id,cm.name,cm.pages_read FROM club_members cm JOIN book_clubs bc ON bc.id=cm.club_id WHERE bc.user_id=$1',[id]),
    await c.query(`SELECT l.app_key AS id,b.app_key AS b,l.reading_date AS d,l.pages_read AS p FROM reading_logs l JOIN books b ON b.id=l.book_id WHERE b.user_id=$1 ORDER BY l.id`,[id])
  ];
  const user=u.rows[0];
  const featured=await c.query('SELECT app_key FROM books WHERE id=$1',[user.featured_book_id]);
  const iso=v=>v instanceof Date ? v.toISOString().slice(0,10) : v || '';
  return {
    user: { name:user.name,avatar:user.avatar||'',theme:user.theme,phrase:user.phrase,featured:featured.rows[0]?.app_key||'',goal:user.annual_goal,calm:user.calm_mode },
    books:b.rows.map(x=>({...x,date:iso(x.date),lentDate:iso(x.lentDate),rating:Number(x.rating),cover:x.cover||''})),
    clubs:cl.rows.map(x=>({id:x.app_key,name:x.name,book:x.monthly_book,goal:x.page_goal,end:iso(x.deadline),members:m.rows.filter(y=>String(y.club_id)===String(x.id)).map(y=>({name:y.name,pages:y.pages_read}))})),
    log:l.rows.map(x=>({...x,d:iso(x.d)}))
  };
}

async function transaction(fn) {
  const c=await db.connect();
  try {
    await c.query('BEGIN');
    await c.query('SELECT pg_advisory_xact_lock(827365)');
    const result=await fn(c);
    await c.query('COMMIT');
    return result;
  } catch(e) { await c.query('ROLLBACK').catch(()=>{}); throw e; }
  finally { c.release(); }
}

app.get('/api/health',async(_req,res)=>{
  try {const r=await db.query('SELECT current_database() AS banco, current_schema() AS esquema');res.json({connected:true,...r.rows[0]});}
  catch(e){res.status(500).json({connected:false,error:e.message});}
});

app.get('/api/state',requireAuth,async(req,res)=>{
  try {
    const state=await transaction(async c=>{
      const id=req.auth.id;
      const count=await c.query('SELECT COUNT(*)::int AS n FROM books WHERE user_id=$1',[id]);
      const clubs=await c.query('SELECT COUNT(*)::int AS n FROM book_clubs WHERE user_id=$1',[id]);
      const logs=await c.query('SELECT COUNT(*)::int AS n FROM reading_logs l JOIN books b ON b.id=l.book_id WHERE b.user_id=$1',[id]);
      // Importação única e segura: só migra JSONB se o banco relacional estiver vazio.
      if (process.env.LEGACY_OWNER_EMAIL?.trim().toLowerCase()===req.auth.email && !count.rows[0].n && !clubs.rows[0].n && !logs.rows[0].n) {
        const migrated=await c.query("SELECT migrated_at FROM public.amber_pages_migration WHERE id='principal'");
        const exists=await c.query("SELECT to_regclass('public.amber_pages_state') AS tabela");
        if(exists.rows[0].tabela && !migrated.rows.length) {
          const old=await c.query("SELECT data FROM public.amber_pages_state WHERE id='principal'");
          if(old.rows[0]?.data && Array.isArray(old.rows[0].data.books)) {
            await writeState(c,old.rows[0].data,id);
            await c.query("INSERT INTO public.amber_pages_migration(id,migrated_at) VALUES('principal',NOW()) ON CONFLICT(id) DO UPDATE SET migrated_at=EXCLUDED.migrated_at");
            console.log('Dados antigos migrados para as tabelas relacionais.');
          }
        }
      }
      const result=await readState(c,id);
      // Na primeira utilização, o HTML pode enviar o backup local.
      const empty=!result.books.length&&!result.clubs.length&&!result.log.length;
      return empty ? null : result;
    });
    res.json({state});
  }catch(e){console.error('GET /api/state:',e);res.status(500).json({error:e.message});}
});

app.put('/api/state',requireAuth,async(req,res)=>{
  const s=req.body;
  if(!s||!s.user||!Array.isArray(s.books)||!Array.isArray(s.clubs)||!Array.isArray(s.log))
    return res.status(400).json({error:'Estado inválido: user, books, clubs e log são obrigatórios.'});
  try {
    await transaction(async c=>{const id=req.auth.id;await writeState(c,s,id);await c.query("INSERT INTO public.amber_pages_migration(id,migrated_at) VALUES('principal',NOW()) ON CONFLICT(id) DO UPDATE SET migrated_at=EXCLUDED.migrated_at");});
    res.json({saved:true,storage:'relational'});
  }catch(e){console.error('PUT /api/state:',e);res.status(500).json({error:e.message});}
});


// Catálogo bibliográfico compartilhado: separado da estante pessoal (books).
// Pesquisar NÃO adiciona automaticamente o livro à biblioteca do usuário.
const catalogReady = (async () => {
  await db.query(`CREATE TABLE IF NOT EXISTS public.catalog_books (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    title VARCHAR(300) NOT NULL,
    author VARCHAR(300) NOT NULL DEFAULT '',
    isbn VARCHAR(20),
    pages INTEGER NOT NULL DEFAULT 0,
    synopsis TEXT NOT NULL DEFAULT '',
    cover TEXT NOT NULL DEFAULT '',
    source VARCHAR(40) NOT NULL,
    source_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await db.query('CREATE INDEX IF NOT EXISTS catalog_books_title_idx ON public.catalog_books (LOWER(title))');
  await db.query('CREATE INDEX IF NOT EXISTS catalog_books_author_idx ON public.catalog_books (LOWER(author))');
})();
catalogReady.catch(err => console.error('Erro ao preparar catalog_books:', err.message));

const normalizeCatalog = value => String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const cleanCatalog = (v, n = 300) => String(v || '').trim().slice(0, n);
const isbnOf = ids => (ids || []).find(x => x.type === 'ISBN_13')?.identifier || (ids || []).find(x => x.type === 'ISBN_10')?.identifier || '';
const bookKey = b => b.isbn ? 'isbn|'+b.isbn.replace(/[^0-9X]/gi,'') : 'edition|'+normalizeCatalog(b.title)+'|'+normalizeCatalog(b.author)+'|'+normalizeCatalog(b.publisher)+'|'+normalizeCatalog(b.year)+'|'+normalizeCatalog(b.sourceId);
const isIsbn = q => /^(?:97[89])?\d{9}[\dX]$/i.test(q.replace(/[\s-]/g, ''));
async function getCatalogJSON(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 7500);
  try {
    const response = await fetch(url, {signal: controller.signal, headers: {'Accept': 'application/json'}});
    if (!response.ok) throw new Error('API externa HTTP ' + response.status);
    return await response.json();
  } finally { clearTimeout(timer); }
}
function googleBooks(items) {
  return (items || []).map(item => {
    const v = item.volumeInfo || {}, images = v.imageLinks || {};
    return { title: cleanCatalog(v.title), author: cleanCatalog((v.authors || []).join(', ')),
      isbn: cleanCatalog(isbnOf(v.industryIdentifiers), 20), pages: Math.max(0, Number(v.pageCount) || 0),
      synopsis: cleanCatalog(String(v.description || '').replace(/<[^>]*>/g, ''), 4000),
      cover: cleanCatalog(images.thumbnail || images.smallThumbnail || '', 1000).replace(/^http:/, 'https:'),
      language: cleanCatalog(v.language,12), publisher:cleanCatalog(v.publisher), year:cleanCatalog(v.publishedDate,20), source: 'google', sourceId: String(item.id || '') };
  }).filter(x => x.title);
}
function openLibraryBooks(docs) {
  return (docs || []).map(v => ({title: cleanCatalog(v.title), author: cleanCatalog((v.author_name || []).join(', ')),
    isbn: cleanCatalog((v.isbn || [])[0], 20), pages: Math.max(0, Number(v.number_of_pages_median) || 0),
    synopsis: '', cover: v.cover_i ? 'https://covers.openlibrary.org/b/id/' + v.cover_i + '-M.jpg' : '',
    language:cleanCatalog((v.language||[])[0],12), publisher:cleanCatalog((v.publisher||[])[0]), year:cleanCatalog(v.first_publish_year,20), source: 'openlibrary', sourceId: String(v.key || '')})).filter(x => x.title);
}

async function fetchEditions(docs){
 const keys=[...new Set((docs||[]).map(x=>x.key).filter(x=>/^\/works\/OL\d+W$/.test(x||'')))].slice(0,2);
 const settled=await Promise.allSettled(keys.map(k=>getCatalogJSON('https://openlibrary.org'+k+'/editions.json?limit=12')));
 return settled.flatMap(r=>r.status==='fulfilled'?(r.value.entries||[]).map(e=>({title:cleanCatalog(e.title),author:cleanCatalog(e.by_statement||''),isbn:cleanCatalog((e.isbn_13||e.isbn_10||[])[0],20),pages:Number(e.number_of_pages)||0,synopsis:'',cover:(e.covers||[])[0]>0?'https://covers.openlibrary.org/b/id/'+e.covers[0]+'-M.jpg':'',language:cleanCatalog((e.languages||[])[0]?.key?.split('/').pop(),12),publisher:cleanCatalog((e.publishers||[])[0]),year:cleanCatalog(e.publish_date,30),source:'openlibrary-edition',sourceId:cleanCatalog(e.key)})).filter(e=>e.title):[]);
}
app.get('/api/catalog/search', async (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 120);
  if (!q) return res.status(400).json({error: 'Informe título, autor ou ISBN.'});
  try {
    await catalogReady;
    const numericIsbn = q.replace(/[\s-]/g, '');
    const isbn = isIsbn(q);
    const googleURL = new URL('https://www.googleapis.com/books/v1/volumes');
    googleURL.searchParams.set('q', isbn ? 'isbn:' + numericIsbn : q);
    googleURL.searchParams.set('maxResults', '25');
    googleURL.searchParams.set('printType', 'books');
    if (process.env.GOOGLE_BOOKS_API_KEY) googleURL.searchParams.set('key', process.env.GOOGLE_BOOKS_API_KEY);
    const googleBR = new URL(googleURL); googleBR.searchParams.set('langRestrict','pt'); googleBR.searchParams.set('country','BR');
    const openURL = new URL('https://openlibrary.org/search.json');
    openURL.searchParams.set(isbn ? 'isbn' : 'q', isbn ? numericIsbn : q);
    openURL.searchParams.set('limit', '15');
    openURL.searchParams.set('fields', 'key,title,author_name,isbn,cover_i,number_of_pages_median,language,publisher,first_publish_year');
    const results = await Promise.allSettled([getCatalogJSON(googleBR),getCatalogJSON(googleURL), getCatalogJSON(openURL)]);
    const found = [];
    if (results[0].status === 'fulfilled') found.push(...googleBooks(results[0].value.items));
    if (results[1].status === 'fulfilled') found.push(...googleBooks(results[1].value.items));
    if (results[2].status === 'fulfilled') { found.push(...openLibraryBooks(results[2].value.docs)); found.push(...await fetchEditions(results[2].value.docs)); }
    const unique = new Map();
    for (const b of found) {
      const fingerprint = bookKey(b);
      if (fingerprint && !unique.has(fingerprint)) unique.set(fingerprint, b);
    }
    const sorted=[...unique.values()].sort((a,b)=>Number(!['pt','por','pt-br'].includes((a.language||'').toLowerCase()))-Number(!['pt','por','pt-br'].includes((b.language||'').toLowerCase())));
    // Grava os metadados descobertos no catálogo do Neon, sem alterar o estado da estante pessoal.
    if (unique.size) {
      const client = await db.connect();
      try {
        await client.query('BEGIN');
        for (const [fingerprint, b] of unique) {
          await client.query(`INSERT INTO public.catalog_books
            (fingerprint,title,author,isbn,pages,synopsis,cover,source,source_id)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT(fingerprint) DO UPDATE SET
            isbn=COALESCE(NULLIF(EXCLUDED.isbn,''),catalog_books.isbn),
            pages=CASE WHEN EXCLUDED.pages > 0 THEN EXCLUDED.pages ELSE catalog_books.pages END,
            synopsis=CASE WHEN EXCLUDED.synopsis <> '' THEN EXCLUDED.synopsis ELSE catalog_books.synopsis END,
            cover=CASE WHEN EXCLUDED.cover <> '' THEN EXCLUDED.cover ELSE catalog_books.cover END,
            updated_at=NOW()`,
            [fingerprint,b.title,b.author,b.isbn,Math.trunc(b.pages),b.synopsis,b.cover,b.source,b.sourceId]);
        }
        await client.query('COMMIT');
      } catch (error) { await client.query('ROLLBACK').catch(()=>{}); console.error('Falha no cache do catálogo:',error.message); }
      finally { client.release(); }
      return res.json({source:'external', books:sorted});
    }
    // Nenhum resultado externo: primeiro catálogo persistido, depois livros da estante pessoal.
    const like = '%' + q + '%';
    const catalog = await db.query(`SELECT title,author,pages,synopsis,cover,isbn,source FROM public.catalog_books
      WHERE title ILIKE $1 OR author ILIKE $1 OR isbn = $2
      ORDER BY title LIMIT 30`,[like,numericIsbn]);
    if (catalog.rows.length) return res.json({source:'neon_catalog',books:catalog.rows});
    const personal = {rows:[]}; // Dados privados nunca são resultados de busca pública.
    const failed = results.every(r=>r.status==='rejected');
    return res.json({source:'neon_books',books:personal.rows,
      warning:failed?'As APIs externas estão indisponíveis; foram consultados apenas os dados do Neon.':''});
  } catch (error) {
    console.error('GET /api/catalog/search:',error);
    res.status(500).json({error:'Não foi possível concluir a pesquisa: '+error.message});
  }
});


// Comunidade: publicações voluntárias, sem expor automaticamente a biblioteca privada.
const communityReady = (async () => {
  await authReady;
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_follows (
    follower_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    followed_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (follower_id, followed_id), CHECK (follower_id <> followed_id))`);
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_posts (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    content TEXT NOT NULL CHECK (char_length(content) BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await db.query('CREATE INDEX IF NOT EXISTS amber_posts_recent_idx ON public.amber_posts(created_at DESC)');
  // Migração aditiva: publicações antigas continuam como texto livre.
  await db.query(`ALTER TABLE public.amber_posts ADD COLUMN IF NOT EXISTS post_type TEXT NOT NULL DEFAULT 'livre'`);
  await db.query(`ALTER TABLE public.amber_posts ADD COLUMN IF NOT EXISTS book_title TEXT`);
  await db.query(`ALTER TABLE public.amber_posts ADD COLUMN IF NOT EXISTS book_author TEXT`);
  await db.query(`ALTER TABLE public.amber_posts ADD COLUMN IF NOT EXISTS book_cover TEXT`);
  await db.query(`ALTER TABLE public.amber_posts ADD COLUMN IF NOT EXISTS rating SMALLINT`);
  await db.query(`ALTER TABLE public.amber_posts ADD COLUMN IF NOT EXISTS spoiler BOOLEAN NOT NULL DEFAULT FALSE`);
  await db.query(`ALTER TABLE public.amber_posts DROP CONSTRAINT IF EXISTS amber_posts_content_check`);
  await db.query(`ALTER TABLE public.amber_posts ADD CONSTRAINT amber_posts_content_check CHECK (char_length(content) BETWEEN 1 AND 2000)`);
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_likes (
    post_id BIGINT NOT NULL REFERENCES public.amber_posts(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(post_id,user_id))`);
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_comments (
    id BIGSERIAL PRIMARY KEY, post_id BIGINT NOT NULL REFERENCES public.amber_posts(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    content TEXT NOT NULL CHECK (char_length(content) BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await db.query(`CREATE INDEX IF NOT EXISTS amber_comments_post_idx ON public.amber_comments(post_id,created_at)`);
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_notifications (
    id BIGSERIAL PRIMARY KEY, recipient_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    actor_id BIGINT REFERENCES public.users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL, post_id BIGINT REFERENCES public.amber_posts(id) ON DELETE CASCADE,
    message TEXT NOT NULL, read_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await db.query(`CREATE INDEX IF NOT EXISTS amber_notifications_user_idx ON public.amber_notifications(recipient_id,created_at DESC)`);
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_shared_clubs (
    id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, book_title TEXT, description TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_club_members (
    club_id BIGINT NOT NULL REFERENCES public.amber_shared_clubs(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(club_id,user_id))`);
  await db.query(`CREATE TABLE IF NOT EXISTS public.amber_club_messages (
    id BIGSERIAL PRIMARY KEY, club_id BIGINT NOT NULL REFERENCES public.amber_shared_clubs(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    content TEXT NOT NULL CHECK (char_length(content) BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);

})();
communityReady.catch(e=>console.error('Falha ao preparar comunidade:',e));
const community = async (req,res,next) => { try { await communityReady; next(); } catch(e) { next(e); } };
app.get('/api/community/people',requireAuth,community,async(req,res,next)=>{
  try {
    const q=String(req.query.q||'').trim().slice(0,80);
    const r=await db.query(`SELECT u.id::text, u.name,
      EXISTS(SELECT 1 FROM public.amber_follows f WHERE f.follower_id=$1 AND f.followed_id=u.id) AS following
      FROM public.users u JOIN public.amber_auth a ON a.user_id=u.id
      WHERE u.id<>$1 AND ($2='' OR u.name ILIKE '%'||$2||'%') ORDER BY u.name LIMIT 30`,[req.auth.id,q]);
    res.json({people:r.rows});
  }catch(e){next(e)}
});
app.post('/api/community/follow/:id',requireAuth,community,async(req,res,next)=>{
  try {
    const id=String(req.params.id);
    if(!/^\d+$/.test(id)||id===String(req.auth.id)) return res.status(400).json({error:'Leitor inválido.'});
    const r=await db.query(`INSERT INTO public.amber_follows(follower_id,followed_id)
      SELECT $1,u.id FROM public.users u JOIN public.amber_auth a ON a.user_id=u.id WHERE u.id=$2
      ON CONFLICT DO NOTHING RETURNING followed_id`,[req.auth.id,id]);
    if(!r.rowCount){const exists=await db.query('SELECT 1 FROM public.users WHERE id=$1',[id]);if(!exists.rowCount)return res.status(404).json({error:'Leitor não encontrado.'})}
    if(r.rowCount) await db.query(`INSERT INTO public.amber_notifications(recipient_id,actor_id,kind,message)
      VALUES($1,$2,'follow','começou a seguir você')`,[id,req.auth.id]);
    res.json({following:true});
  }catch(e){next(e)}
});
app.delete('/api/community/follow/:id',requireAuth,community,async(req,res,next)=>{
  try {await db.query('DELETE FROM public.amber_follows WHERE follower_id=$1 AND followed_id=$2',[req.auth.id,req.params.id]);res.json({following:false})}catch(e){next(e)}
});
app.get('/api/community/feed',requireAuth,community,async(req,res,next)=>{
  try {
    const r=await db.query(`SELECT p.id::text,p.content,p.created_at,p.post_type,p.book_title,p.book_author,p.book_cover,p.rating,p.spoiler,u.name,p.user_id::text AS author_id,
      (p.user_id=$1) AS mine,
      (SELECT count(*)::int FROM public.amber_likes l WHERE l.post_id=p.id) AS likes,
      EXISTS(SELECT 1 FROM public.amber_likes l WHERE l.post_id=p.id AND l.user_id=$1) AS liked,
      (SELECT count(*)::int FROM public.amber_comments c WHERE c.post_id=p.id) AS comments_count FROM public.amber_posts p JOIN public.users u ON u.id=p.user_id
      WHERE p.user_id=$1 OR EXISTS(SELECT 1 FROM public.amber_follows f WHERE f.follower_id=$1 AND f.followed_id=p.user_id)
      ORDER BY p.created_at DESC,p.id DESC LIMIT 60`,[req.auth.id]);
    res.json({posts:r.rows});
  }catch(e){next(e)}
});
app.post('/api/community/posts',requireAuth,community,async(req,res,next)=>{
  try {
    const content=String(req.body?.content||'').trim();
    const type=String(req.body?.post_type||'livre');
    const allowed=['livre','resenha','comentario','citacao','progresso','concluido'];
    if(!content||content.length>2000)return res.status(400).json({error:'Escreva entre 1 e 2000 caracteres.'});
    if(!allowed.includes(type))return res.status(400).json({error:'Tipo de publicação inválido.'});
    const book=req.body?.book;
    if(type!=='livre'&&(!book||typeof book.title!=='string'||!book.title.trim()))return res.status(400).json({error:'Selecione um livro.'});
    const title=type==='livre'?null:String(book.title).trim().slice(0,250);
    const author=title?String(book.author||'').slice(0,250):null;
    const cover=title?String(book.cover||'').slice(0,1000):null;
    if(cover&&!/^https:\/\//i.test(cover))return res.status(400).json({error:'Endereço de capa inválido.'});
    const rating=Number(req.body?.rating||0);
    if(!Number.isInteger(rating)||rating<0||rating>5)return res.status(400).json({error:'Avaliação inválida.'});
    const r=await db.query(`INSERT INTO public.amber_posts(user_id,content,post_type,book_title,book_author,book_cover,rating,spoiler)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text`,[req.auth.id,content,type,title,author,cover,rating||null,req.body?.spoiler===true]);
    res.status(201).json({id:r.rows[0].id});
  }catch(e){next(e)}
});

// Etapa 6: interações sociais e clubes com persistência por conta.
app.post('/api/community/posts/:id/like',requireAuth,community,async(req,res,next)=>{
 try {const r=await db.query(`INSERT INTO public.amber_likes(post_id,user_id) SELECT id,$2 FROM public.amber_posts WHERE id=$1 ON CONFLICT DO NOTHING RETURNING post_id`,[req.params.id,req.auth.id]);
 if(!r.rowCount){const e=await db.query('SELECT 1 FROM public.amber_posts WHERE id=$1',[req.params.id]);if(!e.rowCount)return res.status(404).json({error:'Publicação não encontrada.'})}
 else await db.query(`INSERT INTO public.amber_notifications(recipient_id,actor_id,kind,post_id,message)
 SELECT user_id,$2,'like',id,'curtiu sua publicação' FROM public.amber_posts WHERE id=$1 AND user_id<>$2`,[req.params.id,req.auth.id]);
 res.json({liked:true})}catch(e){next(e)}
});
app.delete('/api/community/posts/:id/like',requireAuth,community,async(req,res,next)=>{
 try{await db.query('DELETE FROM public.amber_likes WHERE post_id=$1 AND user_id=$2',[req.params.id,req.auth.id]);res.json({liked:false})}catch(e){next(e)}
});
app.get('/api/community/posts/:id/comments',requireAuth,community,async(req,res,next)=>{
 try{const r=await db.query(`SELECT c.id::text,c.content,c.created_at,u.name,(c.user_id=$2) AS mine FROM public.amber_comments c JOIN public.users u ON u.id=c.user_id WHERE c.post_id=$1 ORDER BY c.created_at ASC LIMIT 100`,[req.params.id,req.auth.id]);res.json({comments:r.rows})}catch(e){next(e)}
});
app.post('/api/community/posts/:id/comments',requireAuth,community,async(req,res,next)=>{
 try{const content=String(req.body?.content||'').trim();if(!content||content.length>1000)return res.status(400).json({error:'Comentário deve ter entre 1 e 1000 caracteres.'});
 const r=await db.query(`INSERT INTO public.amber_comments(post_id,user_id,content) SELECT id,$2,$3 FROM public.amber_posts WHERE id=$1 RETURNING id::text`,[req.params.id,req.auth.id,content]);if(!r.rowCount)return res.status(404).json({error:'Publicação não encontrada.'});
 await db.query(`INSERT INTO public.amber_notifications(recipient_id,actor_id,kind,post_id,message) SELECT user_id,$2,'comment',id,'comentou sua publicação' FROM public.amber_posts WHERE id=$1 AND user_id<>$2`,[req.params.id,req.auth.id]);res.status(201).json({id:r.rows[0].id})}catch(e){next(e)}
});
app.delete('/api/community/comments/:id',requireAuth,community,async(req,res,next)=>{
 try{const r=await db.query('DELETE FROM public.amber_comments WHERE id=$1 AND user_id=$2',[req.params.id,req.auth.id]);res.status(r.rowCount?200:404).json({deleted:!!r.rowCount})}catch(e){next(e)}
});
app.get('/api/community/notifications',requireAuth,community,async(req,res,next)=>{
 try{const r=await db.query(`SELECT n.id::text,n.kind,n.message,n.post_id::text,n.created_at,n.read_at,u.name AS actor_name FROM public.amber_notifications n LEFT JOIN public.users u ON u.id=n.actor_id WHERE n.recipient_id=$1 ORDER BY n.created_at DESC LIMIT 50`,[req.auth.id]);res.json({notifications:r.rows})}catch(e){next(e)}
});
app.post('/api/community/notifications/read',requireAuth,community,async(req,res,next)=>{
 try{await db.query('UPDATE public.amber_notifications SET read_at=NOW() WHERE recipient_id=$1 AND read_at IS NULL',[req.auth.id]);res.json({ok:true})}catch(e){next(e)}
});
app.get('/api/community/clubs',requireAuth,community,async(req,res,next)=>{
 try{const r=await db.query(`SELECT c.id::text,c.name,c.book_title,c.description,u.name AS owner_name,(c.owner_id=$1) AS mine,
 EXISTS(SELECT 1 FROM public.amber_club_members m WHERE m.club_id=c.id AND m.user_id=$1) AS joined,
 (SELECT count(*)::int FROM public.amber_club_members m WHERE m.club_id=c.id) AS members FROM public.amber_shared_clubs c JOIN public.users u ON u.id=c.owner_id ORDER BY c.created_at DESC LIMIT 80`,[req.auth.id]);res.json({clubs:r.rows})}catch(e){next(e)}
});
app.post('/api/community/clubs',requireAuth,community,async(req,res,next)=>{
 let c;try{const name=String(req.body?.name||'').trim().slice(0,100),book=String(req.body?.book||'').trim().slice(0,200),desc=String(req.body?.description||'').trim().slice(0,500);if(!name)return res.status(400).json({error:'Informe o nome do clube.'});c=await db.connect();await c.query('BEGIN');const r=await c.query('INSERT INTO public.amber_shared_clubs(owner_id,name,book_title,description) VALUES($1,$2,$3,$4) RETURNING id',[req.auth.id,name,book,desc]);await c.query('INSERT INTO public.amber_club_members(club_id,user_id) VALUES($1,$2)',[r.rows[0].id,req.auth.id]);await c.query('COMMIT');res.status(201).json({id:String(r.rows[0].id)})}catch(e){if(c)await c.query('ROLLBACK').catch(()=>{});next(e)}finally{c?.release()}
});
app.post('/api/community/clubs/:id/join',requireAuth,community,async(req,res,next)=>{
 try{const r=await db.query(`INSERT INTO public.amber_club_members(club_id,user_id) SELECT id,$2 FROM public.amber_shared_clubs WHERE id=$1 ON CONFLICT DO NOTHING RETURNING club_id`,[req.params.id,req.auth.id]);res.status(r.rowCount?200:200).json({joined:true})}catch(e){next(e)}
});
app.delete('/api/community/clubs/:id/join',requireAuth,community,async(req,res,next)=>{
 try{await db.query(`DELETE FROM public.amber_club_members WHERE club_id=$1 AND user_id=$2 AND NOT EXISTS(SELECT 1 FROM public.amber_shared_clubs WHERE id=$1 AND owner_id=$2)`,[req.params.id,req.auth.id]);res.json({joined:false})}catch(e){next(e)}
});
app.get('/api/community/clubs/:id/messages',requireAuth,community,async(req,res,next)=>{
 try{const r=await db.query(`SELECT m.id::text,m.content,m.created_at,u.name FROM public.amber_club_messages m JOIN public.users u ON u.id=m.user_id WHERE m.club_id=$1 AND EXISTS(SELECT 1 FROM public.amber_club_members WHERE club_id=$1 AND user_id=$2) ORDER BY m.created_at DESC LIMIT 80`,[req.params.id,req.auth.id]);res.json({messages:r.rows.reverse()})}catch(e){next(e)}
});
app.post('/api/community/clubs/:id/messages',requireAuth,community,async(req,res,next)=>{
 try{const content=String(req.body?.content||'').trim();if(!content||content.length>1000)return res.status(400).json({error:'Mensagem inválida.'});const r=await db.query(`INSERT INTO public.amber_club_messages(club_id,user_id,content) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM public.amber_club_members WHERE club_id=$1 AND user_id=$2) RETURNING id`,[req.params.id,req.auth.id,content]);if(!r.rowCount)return res.status(403).json({error:'Entre no clube para participar.'});res.status(201).json({ok:true})}catch(e){next(e)}
});

app.delete('/api/community/posts/:id',requireAuth,community,async(req,res,next)=>{
  try {const r=await db.query('DELETE FROM public.amber_posts WHERE id=$1 AND user_id=$2',[req.params.id,req.auth.id]);res.status(r.rowCount?200:404).json(r.rowCount?{deleted:true}:{error:'Publicação não encontrada.'})}catch(e){next(e)}
});

app.use(express.static(__dirname,{index:'index.html'}));
app.listen(PORT,()=>console.log(`Amber Pages: http://localhost:${PORT}`));
