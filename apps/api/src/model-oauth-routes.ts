import { createHash, createHmac } from "node:crypto";
import type { PiOAuthConnected, PiOAuthLogins } from "@rakazo/adapters";
import {
  CHATGPT_OAUTH_PROVIDER,
  DEFAULT_OPENAI_REDIRECT_URI,
  OPENAI_OAUTH_ISSUER,
  OPENAI_OAUTH_REDIRECT_URI_ENV,
  OPENAI_OAUTH_STATE_TTL_SECONDS,
  timingSafeEqualStrings,
  validateOpenAiRedirectUri,
} from "@rakazo/adapters";
import type { Actor, ModelCredential, ThinkingLevel } from "@rakazo/contracts";
import { ThinkingLevelSchema } from "@rakazo/contracts";
import { runAsTenant } from "@rakazo/db";
import { renderTokensCss } from "@rakazo/ui-tokens";
import type { Hono } from "hono";

export const OPENAI_CODEX_OAUTH_START_PATH = "/api/oauth/openai-codex/start";
export const OPENAI_CODEX_OAUTH_CALLBACK_PATH = "/api/oauth/openai-codex/callback";
export const OPENAI_CODEX_OAUTH_COOKIE_NAME = "rakazo_openai_oauth";

const FORBIDDEN_REDIRECT_PARAMS = [
  "redirect",
  "redirect_to",
  "redirect_uri",
  "next",
  "returnTo",
  "return_to",
  "callback",
  "url",
  "target",
] as const;

const AUTHORITY_HOST_PATTERN =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*|\[[0-9a-f:]+\])(?::\d{1,5})?$/i;

export type ResolveOpenAiCallbackRedirectOptions = {
  request?: Request;
  webOrigin?: string;
  env?: NodeJS.ProcessEnv;
};

function firstHeaderToken(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const first = value.split(",")[0]?.trim();
  return first || undefined;
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "[::1]";
}

function isValidAuthorityHost(authority: string): boolean {
  if (!authority || authority.length > 260) return false;
  if (!AUTHORITY_HOST_PATTERN.test(authority)) return false;
  try {
    const parsed = new URL(`https://${authority}`);
    if (
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    ) {
      return false;
    }
    if (parsed.port) {
      const port = Number(parsed.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function resolveOpenAiCallbackRedirectUri(
  options: ResolveOpenAiCallbackRedirectOptions = {},
): string {
  const env = options.env ?? process.env;
  const configured = env[OPENAI_OAUTH_REDIRECT_URI_ENV]?.trim();
  if (configured) {
    return validateOpenAiRedirectUri(configured);
  }

  if (options.request) {
    const forwardedProto = firstHeaderToken(
      options.request.headers.get("x-forwarded-proto"),
    )?.toLowerCase();
    const forwardedHost = firstHeaderToken(options.request.headers.get("x-forwarded-host"));
    const hostHeader = firstHeaderToken(options.request.headers.get("host"));
    let requestUrl: URL | undefined;
    try {
      requestUrl = new URL(options.request.url);
    } catch {
      requestUrl = undefined;
    }

    const authority = forwardedHost ?? hostHeader ?? requestUrl?.host;
    if (authority && isValidAuthorityHost(authority)) {
      const hostname = new URL(`https://${authority}`).hostname;
      const protocol =
        forwardedProto === "https" || forwardedProto === "http"
          ? forwardedProto
          : requestUrl?.protocol === "https:"
            ? "https"
            : isLoopbackHostname(hostname)
              ? "http"
              : undefined;

      if (protocol === "https" || (protocol === "http" && isLoopbackHostname(hostname))) {
        try {
          return validateOpenAiRedirectUri(
            new URL(OPENAI_CODEX_OAUTH_CALLBACK_PATH, `${protocol}://${authority}`).toString(),
          );
        } catch {
          // Fall through to webOrigin or default redirect URI.
        }
      }
    }
  }

  if (options.webOrigin?.trim()) {
    try {
      return validateOpenAiRedirectUri(
        new URL(OPENAI_CODEX_OAUTH_CALLBACK_PATH, options.webOrigin.trim()).toString(),
      );
    } catch {
      // Fall through to default loopback redirect URI.
    }
  }

  return DEFAULT_OPENAI_REDIRECT_URI;
}

type OAuthBindingCookiePayload = {
  loginId: string;
  userId: string;
  spaceId: string;
  state: string;
  exp: number;
};

function signBindingCookie(payload: OAuthBindingCookiePayload, secret: string): string {
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verifyBindingCookie(
  cookieValue: string,
  secret: string,
): OAuthBindingCookiePayload | null {
  const parts = cookieValue.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  const expectedSignature = createHmac("sha256", secret).update(parts[0]).digest("base64url");
  if (!timingSafeEqualStrings(parts[1], expectedSignature)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const record = parsed as Record<string, unknown>;
    if (
      typeof record.loginId !== "string" ||
      typeof record.userId !== "string" ||
      typeof record.spaceId !== "string" ||
      typeof record.state !== "string" ||
      typeof record.exp !== "number"
    ) {
      return null;
    }
    if (record.exp <= Date.now()) return null;
    return {
      loginId: record.loginId,
      userId: record.userId,
      spaceId: record.spaceId,
      state: record.state,
      exp: record.exp,
    };
  } catch {
    return null;
  }
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [rawKey, ...rest] = part.trim().split("=");
    if (rawKey === name) {
      return rest.join("=").trim() || undefined;
    }
  }
  return undefined;
}

function formatBindingCookie(value: string, maxAgeSeconds: number, secure: boolean): string {
  const attributes = [
    `${OPENAI_CODEX_OAUTH_COOKIE_NAME}=${value}`,
    ` Path=${OPENAI_CODEX_OAUTH_CALLBACK_PATH}`,
    ` Max-Age=${maxAgeSeconds}`,
    " HttpOnly",
    " SameSite=Lax",
  ];
  if (secure) attributes.push(" Secure");
  return attributes.join(";");
}

export function createOpenAiOAuthBindingCookieHeader(options: {
  loginId: string;
  userId: string;
  spaceId: string;
  verificationUri: string;
  redirectUri?: string;
  request?: Request;
  authSecret: string;
}): string | undefined {
  let state: string | undefined;
  try {
    state = new URL(options.verificationUri).searchParams.get("state")?.trim() || undefined;
  } catch {
    return undefined;
  }
  if (!state) return undefined;
  let requestUrl: URL | undefined;
  if (options.request) {
    try {
      requestUrl = new URL(options.request.url);
    } catch {
      requestUrl = undefined;
    }
  }
  const isSecure =
    (options.redirectUri?.startsWith("https://") ?? false) ||
    firstHeaderToken(options.request?.headers.get("x-forwarded-proto"))?.toLowerCase() ===
      "https" ||
    requestUrl?.protocol === "https:";
  const cookieValue = signBindingCookie(
    {
      loginId: options.loginId,
      userId: options.userId,
      spaceId: options.spaceId,
      state,
      exp: Date.now() + OPENAI_OAUTH_STATE_TTL_SECONDS * 1000,
    },
    options.authSecret,
  );
  return formatBindingCookie(cookieValue, OPENAI_OAUTH_STATE_TTL_SECONDS, isSecure);
}

export function clearOpenAiOAuthBindingCookieHeader(options?: { request?: Request }): string {
  let requestUrl: URL | undefined;
  if (options?.request) {
    try {
      requestUrl = new URL(options.request.url);
    } catch {
      requestUrl = undefined;
    }
  }
  const isSecure =
    firstHeaderToken(options?.request?.headers.get("x-forwarded-proto"))?.toLowerCase() ===
      "https" || requestUrl?.protocol === "https:";
  return formatBindingCookie("", 0, isSecure);
}

const CALLBACK_TOKENS_CSS = renderTokensCss();

function hasForbiddenRedirectParam(url: URL, body?: Record<string, unknown>): boolean {
  for (const param of FORBIDDEN_REDIRECT_PARAMS) {
    if (url.searchParams.has(param)) return true;
    if (body && param in body && body[param] !== undefined) return true;
  }
  return false;
}

function wantsJsonResponse(request: Request, url: URL): boolean {
  if (request.method === "POST") return true;
  if (url.searchParams.get("format") === "json") return true;
  const accept = request.headers.get("accept") ?? "";
  return accept.includes("application/json") && !accept.includes("text/html");
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderOAuthCallbackHtml(options: {
  ok: boolean;
  title: string;
  message: string;
  loginId?: string;
}): { html: string; csp: string } {
  const scriptContent =
    options.ok && options.loginId
      ? `try{const c=new BroadcastChannel("rakazo:model-oauth");c.postMessage(${JSON.stringify({
          type: "completed",
          loginId: options.loginId,
          provider: CHATGPT_OAUTH_PROVIDER,
        })});c.close();}catch{}try{window.close();}catch{}`
      : "";
  const scriptHash = scriptContent
    ? `'sha256-${createHash("sha256").update(scriptContent, "utf8").digest("base64")}'`
    : "'none'";
  const csp = `default-src 'none'; style-src 'unsafe-inline'; script-src ${scriptHash}; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`;
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="referrer" content="no-referrer" />
    <title>${escapeHtml(options.title)}</title>
    <style>
${CALLBACK_TOKENS_CSS}
      body { font-family: system-ui, -apple-system, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--background); color: var(--foreground); }
      main { max-width: 26rem; padding: 1.5rem; text-align: center; }
      h1 { font-size: 1.125rem; font-weight: 600; margin: 0 0 0.5rem; }
      p { font-size: 0.875rem; color: var(--muted-foreground); margin: 0; line-height: 1.5; }
    </style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(options.title)}</h1>
      <p>${escapeHtml(options.message)}</p>
    </main>${scriptContent ? `\n    <script>${scriptContent}</script>` : ""}
  </body>
</html>`;
  return { html, csp };
}

export type ModelOAuthRoutesDeps = {
  oauthLogins: PiOAuthLogins;
  authSecret: string;
  webOrigin: string;
  authenticate: (
    request: Request,
    spaceIdOverride?: string | null,
  ) => Promise<{
    actor: Actor | null;
    authenticatedUser: boolean;
  }>;
  persistOAuthCredential: (actor: Actor, login: PiOAuthConnected) => Promise<ModelCredential>;
};

export function mountModelOAuthRoutes(app: Hono, deps: ModelOAuthRoutesDeps): void {
  app.use("/api/oauth/*", async (c, next) => {
    await next();
    c.header("cache-control", "no-store");
    c.header("pragma", "no-cache");
    c.header("referrer-policy", "no-referrer");
  });

  app.on(["GET", "POST"], OPENAI_CODEX_OAUTH_START_PATH, async (c) => {
    const requestUrl = new URL(c.req.url);
    let body: Record<string, unknown> | undefined;
    if (c.req.method === "POST") {
      const contentType = c.req.header("content-type") ?? "";
      if (contentType.includes("application/json")) {
        try {
          const parsed = await c.req.json<unknown>();
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            body = parsed as Record<string, unknown>;
          }
        } catch {
          return c.json({ error: "Invalid JSON request body." }, 400);
        }
      }
    }

    if (hasForbiddenRedirectParam(requestUrl, body)) {
      return c.json({ error: "Custom redirect targets are not allowed." }, 400);
    }

    const requestedSpaceId =
      (typeof body?.spaceId === "string" ? body.spaceId.trim() : undefined) ||
      requestUrl.searchParams.get("spaceId")?.trim() ||
      c.req.header("x-rakazo-space-id")?.trim() ||
      null;

    const { actor, authenticatedUser } = await deps.authenticate(c.req.raw, requestedSpaceId);
    if (!authenticatedUser) {
      return c.json({ error: "Authentication required." }, 401);
    }
    if (!actor) {
      return c.json({ error: "You do not have access to this space." }, 403);
    }

    const modelId =
      (typeof body?.modelId === "string" ? body.modelId.trim() : undefined) ||
      requestUrl.searchParams.get("modelId")?.trim() ||
      undefined;
    const label =
      (typeof body?.label === "string" ? body.label.trim() : undefined) ||
      requestUrl.searchParams.get("label")?.trim() ||
      undefined;
    const rawThinking =
      body?.thinkingLevel !== undefined
        ? body.thinkingLevel
        : requestUrl.searchParams.get("thinkingLevel");
    let thinkingLevel: ThinkingLevel | null | undefined;
    if (rawThinking !== undefined && rawThinking !== null && rawThinking !== "") {
      const parsedThinking = ThinkingLevelSchema.safeParse(rawThinking);
      if (!parsedThinking.success) {
        return c.json({ error: "Invalid thinking level." }, 400);
      }
      thinkingLevel = parsedThinking.data;
    } else if (rawThinking === null) {
      thinkingLevel = null;
    }

    let redirectUri: string;
    try {
      redirectUri = resolveOpenAiCallbackRedirectUri({
        request: c.req.raw,
        webOrigin: deps.webOrigin,
      });
    } catch (error) {
      return c.json(
        {
          error:
            error instanceof Error
              ? error.message
              : "Invalid OpenAI OAuth redirect URI configuration.",
        },
        400,
      );
    }

    try {
      const started = await deps.oauthLogins.begin({
        userId: actor.userId,
        spaceId: actor.spaceId,
        provider: CHATGPT_OAUTH_PROVIDER,
        mode: "auth-url",
        redirectUri,
        modelId,
        thinkingLevel,
        label,
        signal: c.req.raw.signal,
      });

      const authorizeUrl = new URL(started.verificationUri);
      if (authorizeUrl.origin !== OPENAI_OAUTH_ISSUER) {
        await deps.oauthLogins.cancel(started.loginId, actor);
        return c.json({ error: "Unexpected OAuth authorization origin." }, 500);
      }

      const cookieHeader = createOpenAiOAuthBindingCookieHeader({
        loginId: started.loginId,
        userId: actor.userId,
        spaceId: actor.spaceId,
        verificationUri: started.verificationUri,
        redirectUri,
        request: c.req.raw,
        authSecret: deps.authSecret,
      });
      if (cookieHeader) {
        c.header("set-cookie", cookieHeader);
      }

      if (wantsJsonResponse(c.req.raw, requestUrl)) {
        return c.json(started, 200);
      }
      return c.redirect(started.verificationUri, 302);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not start ChatGPT sign-in.";
      return c.json({ error: message }, 400);
    }
  });

  app.get(OPENAI_CODEX_OAUTH_CALLBACK_PATH, async (c) => {
    const requestUrl = new URL(c.req.url);
    const jsonPreferred = wantsJsonResponse(c.req.raw, requestUrl);
    c.header("set-cookie", clearOpenAiOAuthBindingCookieHeader({ request: c.req.raw }));

    const respond = (
      status: 200 | 400 | 401 | 403 | 409 | 410 | 502,
      payload: {
        ok: boolean;
        code?: string;
        error?: string;
        title: string;
        message: string;
        loginId?: string;
        credential?: ModelCredential;
      },
    ) => {
      if (jsonPreferred) {
        if (payload.ok) {
          return c.json(
            {
              ok: true,
              loginId: payload.loginId,
              credential: payload.credential,
            },
            status,
          );
        }
        return c.json(
          {
            ok: false,
            code: payload.code,
            error: payload.error ?? payload.message,
          },
          status,
        );
      }
      const rendered = renderOAuthCallbackHtml({
        ok: payload.ok,
        title: payload.title,
        message: payload.message,
        loginId: payload.loginId,
      });
      c.header("content-security-policy", rendered.csp);
      return c.html(rendered.html, status);
    };

    if (hasForbiddenRedirectParam(requestUrl)) {
      return respond(400, {
        ok: false,
        code: "invalid_request",
        error: "Custom redirect targets are not allowed.",
        title: "ChatGPT sign-in failed",
        message: "Custom redirect targets are not allowed.",
      });
    }

    const rawCookie = readCookie(c.req.header("cookie") ?? null, OPENAI_CODEX_OAUTH_COOKIE_NAME);
    const boundCookie = rawCookie ? verifyBindingCookie(rawCookie, deps.authSecret) : undefined;
    if (rawCookie && !boundCookie) {
      return respond(403, {
        ok: false,
        code: "forbidden",
        error: "OAuth callback cookie is invalid or expired.",
        title: "ChatGPT sign-in failed",
        message: "OAuth callback cookie is invalid or expired. Start sign-in again.",
      });
    }

    const { actor, authenticatedUser } = await deps.authenticate(
      c.req.raw,
      boundCookie?.spaceId ?? null,
    );
    if (!authenticatedUser) {
      return respond(401, {
        ok: false,
        code: "unauthorized",
        error: "Authentication required.",
        title: "Sign in required",
        message: "Sign in to Rakazo before completing ChatGPT authorization.",
      });
    }
    if (!actor) {
      return respond(403, {
        ok: false,
        code: "forbidden",
        error: "You do not have access to this space.",
        title: "ChatGPT sign-in failed",
        message: "You do not have access to this space.",
      });
    }

    const state = requestUrl.searchParams.get("state")?.trim() ?? "";
    const code = requestUrl.searchParams.get("code")?.trim() ?? "";
    const oauthError = requestUrl.searchParams.get("error")?.trim() ?? "";

    let cookieLoginId = boundCookie?.loginId;
    if (boundCookie) {
      if (boundCookie.userId !== actor.userId || boundCookie.spaceId !== actor.spaceId || !state) {
        return respond(403, {
          ok: false,
          code: "forbidden",
          error: "OAuth callback does not match the active browser session.",
          title: "ChatGPT sign-in failed",
          message: "OAuth callback does not match the active browser session.",
        });
      }
      const cookieMatchesState = timingSafeEqualStrings(boundCookie.state, state);
      const cookieSupersededByActiveState =
        !cookieMatchesState &&
        deps.oauthLogins.isStateSupersededForActor({
          previousState: boundCookie.state,
          currentState: state,
          userId: actor.userId,
          spaceId: actor.spaceId,
          provider: CHATGPT_OAUTH_PROVIDER,
        });
      if (!cookieMatchesState && !cookieSupersededByActiveState) {
        return respond(403, {
          ok: false,
          code: "forbidden",
          error: "OAuth callback does not match the active browser session.",
          title: "ChatGPT sign-in failed",
          message: "OAuth callback does not match the active browser session.",
        });
      }
      if (cookieSupersededByActiveState) {
        cookieLoginId = undefined;
      }
    }

    let expectedRedirectUri: string;
    try {
      expectedRedirectUri = resolveOpenAiCallbackRedirectUri({
        request: c.req.raw,
        webOrigin: deps.webOrigin,
      });
    } catch {
      expectedRedirectUri = DEFAULT_OPENAI_REDIRECT_URI;
    }

    const callbackUrl = new URL(expectedRedirectUri);
    callbackUrl.search = requestUrl.search;

    const requestedSpaceHeader = c.req.header("x-rakazo-space-id")?.trim();
    const enforcedSpaceId = boundCookie?.spaceId ?? requestedSpaceHeader;

    const result = await deps.oauthLogins.completeCallback(
      {
        provider: CHATGPT_OAUTH_PROVIDER,
        userId: actor.userId,
        ...(enforcedSpaceId ? { spaceId: enforcedSpaceId } : {}),
        ...(cookieLoginId ? { loginId: cookieLoginId } : {}),
        state,
        code,
        error: oauthError,
        callbackUrl: callbackUrl.toString(),
      },
      async (login) => {
        const { actor: loginActor } = await deps.authenticate(c.req.raw, login.spaceId);
        if (
          !loginActor ||
          loginActor.userId !== actor.userId ||
          loginActor.spaceId !== login.spaceId
        ) {
          throw new Error("You do not have access to this space.");
        }
        return runAsTenant(loginActor, () => deps.persistOAuthCredential(loginActor, login));
      },
    );

    if (result.status === "connected") {
      return respond(200, {
        ok: true,
        loginId: result.loginId,
        credential: result.value,
        title: "ChatGPT connected",
        message: "Authentication completed. You can close this window and return to Rakazo.",
      });
    }

    const statusByCode: Record<typeof result.code, 400 | 403 | 409 | 410 | 502> = {
      missing_state: 400,
      invalid_state: 400,
      expired_state: 410,
      replayed_state: 409,
      cancelled: 409,
      forbidden: 403,
      provider_error: 400,
      exchange_failed: code ? 502 : 400,
    };

    return respond(statusByCode[result.code], {
      ok: false,
      code: result.code,
      error: result.error,
      title: "ChatGPT sign-in failed",
      message: result.error,
    });
  });
}
