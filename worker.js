
const ALLOWED_ORIGIN = "https://bigmafe.github.io";

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin"
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const headers = corsHeaders(origin);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    if (request.method !== "POST") {
      return Response.json(
        { error: "Método não permitido" },
        { status: 405, headers }
      );
    }

    if (origin !== ALLOWED_ORIGIN) {
      return Response.json(
        { error: "Origem não autorizada" },
        { status: 403, headers }
      );
    }

    try {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return Response.json(
          { error: "Autenticação obrigatória" },
          { status: 401, headers }
        );
      }

      const token = authHeader.slice(7);

      // A verificação real do token Firebase será
      // implementada antes de liberar uploads.
      // Por segurança, uploads permanecem bloqueados.
      return Response.json(
        {
          error: "Upload ainda não habilitado",
          message: "Aguardando integração segura com Firebase Auth"
        },
        { status: 503, headers }
      );
    } catch (error) {
      return Response.json(
        { error: "Erro interno" },
        { status: 500, headers }
      );
    }
  }
};
