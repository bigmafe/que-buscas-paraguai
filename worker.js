
const PROJECT_ID = 'que-buscas-paraguai-1b5b1';
const ALLOWED_ORIGIN = 'https://bigmafe.github.io';
const MAX_BYTES = 5 * 1024 * 1024;
const KEY_PREFIX = 'anuncios/';
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

function cors(origin) {
  const headers = new Headers({ 'Vary': 'Origin' });
  if (origin === ALLOWED_ORIGIN) {
    headers.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    headers.set('Access-Control-Max-Age', '86400');
  }
  return headers;
}

function json(data, status, headers) {
  const h = new Headers(headers);
  h.set('Content-Type', 'application/json; charset=utf-8');
  h.set('Cache-Control', 'no-store');
  return new Response(JSON.stringify(data), { status, headers: h });
}

function decodeBase64Url(input) {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  const bytes = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
  return bytes;
}

async function verifyFirebaseToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Token inválido');

  const header = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[1])));
  const now = Math.floor(Date.now() / 1000);

  if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
    throw new Error('Algoritmo inválido');
  }

  if (
    payload.aud !== PROJECT_ID ||
    payload.iss !== `https://securetoken.google.com/${PROJECT_ID}` ||
    typeof payload.sub !== 'string' ||
    !payload.sub ||
    payload.sub.length > 128 ||
    typeof payload.exp !== 'number' ||
    payload.exp <= now ||
    typeof payload.iat !== 'number' ||
    payload.iat > now + 60 ||
    typeof payload.auth_time !== 'number' ||
    payload.auth_time > now + 60
  ) {
    throw new Error('Token expirado ou de outro projeto');
  }

  const response = await fetch(JWKS_URL);
  if (!response.ok) {
    throw new Error('Falha na verificação de identidade');
  }

  const { keys } = await response.json();
  const jwk = keys.find(
    k => k.kid === header.kid &&
         k.kty === 'RSA' &&
         k.use === 'sig'
  );

  if (!jwk) throw new Error('Chave de assinatura desconhecida');

  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);

  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    decodeBase64Url(parts[2]),
    data
  );

  if (!valid) throw new Error('Assinatura inválida');

  return payload;
}

function firestoreString(field) {
  return field?.stringValue ?? '';
}

function firestoreBool(field) {
  return field?.booleanValue === true;
}

async function readOwnDocument(collection, uid, token) {
  const url =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}` +
    `/databases/(default)/documents/${collection}/${encodeURIComponent(uid)}`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  if (response.status === 404 || response.status === 403) {
    return null;
  }

  if (!response.ok) {
    throw new Error('Não foi possível conferir as permissões');
  }

  const doc = await response.json();
  return doc.fields || {};
}

async function authorizeUploader(token) {
  const payload = await verifyFirebaseToken(token);
  const uid = payload.sub;

  const profile = await readOwnDocument('users', uid, token);

  if (
    profile &&
    firestoreString(profile.role) === 'admin' &&
    firestoreBool(profile.active)
  ) {
    return { uid, role: 'admin' };
  }

  const store = await readOwnDocument('stores', uid, token);

  if (
    store &&
    firestoreString(store.ownerId) === uid &&
    firestoreString(store.status) === 'approved'
  ) {
    return { uid, role: 'seller' };
  }

  return null;
}

function imageType(bytes) {
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) {
    return { mime: 'image/jpeg', ext: 'jpg' };
  }

  if (
    bytes.length >= 8 &&
    [137, 80, 78, 71, 13, 10, 26, 10].every(
      (n, i) => bytes[i] === n
    )
  ) {
    return { mime: 'image/png', ext: 'png' };
  }

  if (
    bytes.length >= 12 &&
    String.fromCharCode(...bytes.slice(0, 4)) === 'RIFF' &&
    String.fromCharCode(...bytes.slice(8, 12)) === 'WEBP'
  ) {
    return { mime: 'image/webp', ext: 'webp' };
  }

  return null;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const headers = cors(origin);
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      if (origin !== ALLOWED_ORIGIN) {
        return json({ error: 'Origem não autorizada' }, 403, headers);
      }

      return new Response(null, {
        status: 204,
        headers
      });
    }

    if (!env.FOTOS) {
      return json({ error: 'Bucket R2 não configurado' }, 503, headers);
    }

    if (
      request.method === 'GET' &&
      url.pathname.startsWith('/images/')
    ) {
      const key = url.pathname.slice('/images/'.length);

      if (
        !/^anuncios\/[a-zA-Z0-9_-]{1,128}\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(key)
      ) {
        return json({ error: 'Imagem inválida' }, 404, headers);
      }

      const object = await env.FOTOS.get(key);

      if (!object) {
        return json({ error: 'Imagem não encontrada' }, 404, headers);
      }

      const h = new Headers(headers);

      h.set(
        'Content-Type',
        object.httpMetadata?.contentType || 'application/octet-stream'
      );

      h.set('Cache-Control', 'public, max-age=3600');
      h.set('X-Content-Type-Options', 'nosniff');

      return new Response(object.body, {
        status: 200,
        headers: h
      });
    }

    if (
      request.method !== 'POST' ||
      url.pathname !== '/upload'
    ) {
      return json(
        { error: 'Rota ou método não permitido' },
        405,
        headers
      );
    }

    if (origin !== ALLOWED_ORIGIN) {
      return json(
        { error: 'Origem não autorizada' },
        403,
        headers
      );
    }

    const authHeader =
      request.headers.get('Authorization') || '';

    if (!authHeader.startsWith('Bearer ')) {
      return json(
        { error: 'Faça login para enviar fotos' },
        401,
        headers
      );
    }

    let uploader;

    try {
      uploader = await authorizeUploader(
        authHeader.slice(7)
      );
    } catch (err) {
      console.error(
        'Falha de autenticação:',
        err.message
      );

      return json(
        { error: 'Não foi possível validar sua sessão' },
        401,
        headers
      );
    }

    if (!uploader) {
      return json(
        { error: 'Conta sem autorização para enviar fotos' },
        403,
        headers
      );
    }

    const contentLength = Number(
      request.headers.get('Content-Length') || 0
    );

    if (contentLength > MAX_BYTES + 1024 * 1024) {
      return json(
        { error: 'Arquivo muito grande (máximo 5 MB)' },
        413,
        headers
      );
    }

    if (
      !(request.headers.get('Content-Type') || '')
        .toLowerCase()
        .startsWith('multipart/form-data;')
    ) {
      return json(
        { error: 'Envie um formulário com o campo file' },
        400,
        headers
      );
    }

    let form;

    try {
      form = await request.formData();
    } catch {
      return json(
        { error: 'Formulário inválido' },
        400,
        headers
      );
    }

    const file = form.get('file');

    if (!(file instanceof File)) {
      return json(
        { error: 'Selecione uma imagem no campo file' },
        400,
        headers
      );
    }

    if (file.size === 0 || file.size > MAX_BYTES) {
      return json(
        { error: 'Imagem deve ter até 5 MB' },
        413,
        headers
      );
    }

    const bytes = new Uint8Array(
      await file.arrayBuffer()
    );

    const type = imageType(bytes);

    if (!type) {
      return json(
        { error: 'Use uma imagem JPG, PNG ou WebP válida' },
        415,
        headers
      );
    }

    const key =
      `${KEY_PREFIX}${uploader.uid}/` +
      `${crypto.randomUUID()}.${type.ext}`;

    try {
      await env.FOTOS.put(key, bytes, {
        httpMetadata: {
          contentType: type.mime
        }
      });
    } catch (err) {
      console.error('Erro ao salvar no R2:', err);

      return json(
        { error: 'Falha ao armazenar a imagem' },
        500,
        headers
      );
    }

    return json(
      {
        ok: true,
        url: `${url.origin}/images/${key}`,
        key
      },
      201,
      headers
    );
  }
};
