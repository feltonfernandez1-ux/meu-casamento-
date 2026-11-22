const COOKIE = 'noivos_sessao';
const SESSAO_SEGUNDOS = 60 * 60 * 12;
const enc = new TextEncoder();

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

async function hmac(chave, texto) {
  const k = await crypto.subtle.importKey('raw', enc.encode(chave), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(texto)));
}

async function senhaCorreta(tentativa, real) {
  return crypto.subtle.timingSafeEqual(await hmac('cmp', tentativa), await hmac('cmp', real));
}

async function criarToken(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSAO_SEGUNDOS;
  return exp + '.' + hex(await hmac(env.ADMIN_PASSWORD, 'sessao.' + exp));
}

async function tokenValido(token, env) {
  if (!token) return false;
  const [exp, sig] = token.split('.');
  if (!exp || !sig || Number(exp) < Date.now() / 1000) return false;
  const esperado = hex(await hmac(env.ADMIN_PASSWORD, 'sessao.' + exp));
  if (esperado.length !== sig.length) return false;
  return crypto.subtle.timingSafeEqual(enc.encode(esperado), enc.encode(sig));
}

function lerCookie(req, nome) {
  for (const parte of (req.headers.get('Cookie') || '').split(';')) {
    const [k, ...v] = parte.trim().split('=');
    if (k === nome) return v.join('=');
  }
  return null;
}

const autenticado = (req, env) => (env.ADMIN_PASSWORD ? tokenValido(lerCookie(req, COOKIE), env) : false);

const limpar = (s, max) => String(s ?? '').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, ' ').trim().slice(0, max);

async function guardar(req, env) {
  if (!(req.headers.get('Content-Type') || '').includes('application/json')) return json({ erro: 'Formato inválido.' }, 415);
  let d;
  try { d = await req.json(); } catch { return json({ erro: 'Pedido inválido.' }, 400); }

  const nome = limpar(d.nome, 100);
  let telefone = String(d.telefone ?? '').replace(/\D/g, '');
  if (telefone.length === 9 && telefone.startsWith('8')) telefone = '258' + telefone; // Moçambique
  const presenca = d.presenca;
  const mensagem = limpar(d.mensagem, 500);

  if (nome.length < 3) return json({ erro: 'Nome inválido.' }, 400);
  if (telefone.length < 9 || telefone.length > 15) return json({ erro: 'Telefone inválido.' }, 400);
  if (presenca !== 'sim' && presenca !== 'nao') return json({ erro: 'Presença inválida.' }, 400);
  const pessoas = presenca === 'sim' ? Math.min(Math.max(parseInt(d.pessoas, 10) || 1, 1), 10) : 0;

  await env.DB.prepare(
    `INSERT INTO confirmacoes (nome, telefone, presenca, pessoas, mensagem)
     VALUES (?1, ?2, ?3, ?4, ?5)
     ON CONFLICT(telefone) DO UPDATE SET
       nome = excluded.nome, presenca = excluded.presenca, pessoas = excluded.pessoas,
       mensagem = excluded.mensagem, atualizado_em = datetime('now')`
  ).bind(nome, telefone, presenca, pessoas, mensagem).run();

  return json({ ok: true });
}

async function login(req, env) {
  if (!env.ADMIN_PASSWORD) return json({ erro: 'Palavra-passe ainda não configurada.' }, 500);
  let d;
  try { d = await req.json(); } catch { return json({ erro: 'Pedido inválido.' }, 400); }
  if (!(await senhaCorreta(String(d.senha ?? ''), env.ADMIN_PASSWORD))) {
    await new Promise((r) => setTimeout(r, 800));
    return json({ erro: 'Palavra-passe incorreta.' }, 401);
  }
  const token = await criarToken(env);
  return json({ ok: true }, 200, {
    'Set-Cookie': `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSAO_SEGUNDOS}`,
  });
}

const logout = () => json({ ok: true }, 200, { 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });

const COLUNAS = 'id, nome, telefone, presenca, pessoas, mensagem, criado_em, atualizado_em';

const csvCel = (v, protegerFormula = true) => {
  let s = String(v ?? '');
  if (protegerFormula && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
};

async function exportarCsv(env) {
  const { results } = await env.DB.prepare(`SELECT ${COLUNAS} FROM confirmacoes ORDER BY nome COLLATE NOCASE`).all();
  const linhas = [['Nome', 'Telefone', 'Presença', 'Pessoas', 'Mensagem', 'Criado em (UTC)', 'Atualizado em (UTC)'].map((c) => csvCel(c)).join(',')];
  for (const r of results) {
    linhas.push([
      csvCel(r.nome), csvCel('+' + r.telefone, false), csvCel(r.presenca === 'sim' ? 'Vem' : 'Não vem'),
      csvCel(r.pessoas), csvCel(r.mensagem), csvCel(r.criado_em), csvCel(r.atualizado_em),
    ].join(','));
  }
  return new Response('\ufeff' + linhas.join('\r\n'), {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="convidados.csv"',
      'Cache-Control': 'no-store',
    },
  });
}

export default {
  async fetch(req, env) {
    const { pathname } = new URL(req.url);
    const m = req.method;
    try {
      if (pathname === '/api/rsvp' && m === 'POST') return await guardar(req, env);
      if (pathname === '/api/login' && m === 'POST') return await login(req, env);
      if (pathname === '/api/logout' && m === 'POST') return logout();

      if (!(await autenticado(req, env))) return json({ erro: 'Não autorizado.' }, 401);

      if (pathname === '/api/lista' && m === 'GET') {
        const { results } = await env.DB.prepare(`SELECT ${COLUNAS} FROM confirmacoes ORDER BY atualizado_em DESC`).all();
        return json({ lista: results });
      }
      if (pathname === '/api/exportar.csv' && m === 'GET') return await exportarCsv(env);

      const apagar = pathname.match(/^\/api\/confirmacao\/(\d+)$/);
      if (apagar && m === 'DELETE') {
        await env.DB.prepare('DELETE FROM confirmacoes WHERE id = ?1').bind(Number(apagar[1])).run();
        return json({ ok: true });
      }
      return json({ erro: 'Não encontrado.' }, 404);
    } catch (e) {
      console.error(e);
      return json({ erro: 'Erro no servidor.' }, 500);
    }
  },
};
