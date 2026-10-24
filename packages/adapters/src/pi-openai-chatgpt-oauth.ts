import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { AuthInteraction, OAuthCredential } from "@earendil-works/pi-ai";
import { readBodyCapped, withAbort } from "./web-ssrf.js";

export const OPENAI_OAUTH_ISSUER = "https://auth.openai.com";
export const OPENAI_AUTHORIZE_URL = "https://auth.openai.com/api/accounts/authorize";
export const OPENAI_TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token";
export const DEFAULT_OPENAI_REDIRECT_URI = "http://localhost:1455/auth/callback";
export const OPENAI_OAUTH_SCOPES = "openid profile email offline_access";
export const MAX_OPENAI_TOKEN_RESPONSE_BYTES = 64 * 1024;
export const OPENAI_OAUTH_STATE_TTL_SECONDS = 10 * 60;

const EXPIRY_MARGIN_MS = 5 * 60 * 1000;
const JWT_AUTH_CLAIM_PATH = "https://api.openai.com/auth";

export const OPENAI_OAUTH_CLIENT_ID_ENV = "OPENAI_OAUTH_CLIENT_ID";
export const OPENAI_OAUTH_CLIENT_SECRET_ENV = "OPENAI_OAUTH_CLIENT_SECRET";
export const OPENAI_OAUTH_REDIRECT_URI_ENV = "OPENAI_OAUTH_REDIRECT_URI";

export type OpenAiOAuthEnvConfig = {
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
};

export type OpenAiChatGptOAuthOptions = {
  fetch?: typeof fetch;
  createRandomValue?: () => string;
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  env?: NodeJS.ProcessEnv;
};

export function timingSafeEqualStrings(left: string, right: string): boolean {
  const leftBuf = Buffer.from(left, "utf8");
  const rightBuf = Buffer.from(right, "utf8");
  if (leftBuf.length !== rightBuf.length) {
    timingSafeEqual(leftBuf, leftBuf);
    return false;
  }
  return timingSafeEqual(leftBuf, rightBuf);
}

export function validateOpenAiRedirectUri(rawRedirectUri: string): string {
  let url: URL;
  try {
    url = new URL(rawRedirectUri.trim());
  } catch {
    throw new Error(
      "OpenAI OAuth redirect URI must use HTTPS or localhost HTTP without query or hash parameters.",
    );
  }
  if (url.username || url.password || url.hash || url.search) {
    throw new Error(
      "OpenAI OAuth redirect URI must use HTTPS or localhost HTTP without query or hash parameters.",
    );
  }
  const isHttps = url.protocol === "https:";
  const isLoopbackHttp =
    url.protocol === "http:" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]");
  if (!isHttps && !isLoopbackHttp) {
    throw new Error(
      "OpenAI OAuth redirect URI must use HTTPS or localhost HTTP without query or hash parameters.",
    );
  }
  return url.toString();
}

export function openAiOAuthConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  overrides: Pick<OpenAiChatGptOAuthOptions, "clientId" | "clientSecret" | "redirectUri"> = {},
): { clientId: string; clientSecret?: string; redirectUri: string } {
  const clientId = (overrides.clientId ?? env[OPENAI_OAUTH_CLIENT_ID_ENV] ?? "").trim();
  if (!clientId) {
    throw new Error(
      "OpenAI OAuth client ID is not configured. Set OPENAI_OAUTH_CLIENT_ID or sign in with a device code.",
    );
  }
  const rawSecret = (overrides.clientSecret ?? env[OPENAI_OAUTH_CLIENT_SECRET_ENV] ?? "").trim();
  const rawRedirectUri = (
    overrides.redirectUri ??
    env[OPENAI_OAUTH_REDIRECT_URI_ENV] ??
    DEFAULT_OPENAI_REDIRECT_URI
  ).trim();
  const redirectUri = validateOpenAiRedirectUri(rawRedirectUri);
  return {
    clientId,
    ...(rawSecret ? { clientSecret: rawSecret } : {}),
    redirectUri,
  };
}

export function createOpenAiChatGptOAuthLogin(options: OpenAiChatGptOAuthOptions = {}) {
  const request = options.fetch ?? fetch;
  const createRandomValue =
    options.createRandomValue ?? (() => randomBytes(32).toString("base64url"));

  return async (interaction: AuthInteraction): Promise<OAuthCredential> => {
    const signal = interaction.signal ?? new AbortController().signal;
    signal.throwIfAborted?.();

    const config = openAiOAuthConfigFromEnv(options.env, {
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      redirectUri: options.redirectUri,
    });

    const verifier = createRandomValue();
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const state = createRandomValue();
    const nonce = createRandomValue();

    const authorizeUrl = new URL(OPENAI_AUTHORIZE_URL);
    authorizeUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: OPENAI_OAUTH_SCOPES,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
      nonce,
    }).toString();

    interaction.notify({
      type: "auth_url",
      url: authorizeUrl.toString(),
      instructions:
        "Complete sign-in with ChatGPT in your browser, or paste the final redirect URL.",
    });

    const input = await interaction.prompt({
      type: "manual_code",
      message: "Complete sign-in in your browser, or paste the callback URL:",
      placeholder: config.redirectUri,
      signal,
    });

    const authorization = parseOpenAiAuthorizationInput(input, config.redirectUri);
    if (!authorization.state) {
      throw new Error("Missing OAuth state.");
    }
    if (!timingSafeEqualStrings(authorization.state, state)) {
      throw new Error("OAuth state mismatch.");
    }
    if (!authorization.code) {
      throw new Error("Missing authorization code.");
    }

    const requestSignal = AbortSignal.any([signal, AbortSignal.timeout(30_000)]);
    const tokenParams = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      code: authorization.code,
      redirect_uri: config.redirectUri,
      code_verifier: verifier,
    });
    if (config.clientSecret) {
      tokenParams.set("client_secret", config.clientSecret);
    }

    let response: Response;
    try {
      response = await request(OPENAI_TOKEN_URL, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: tokenParams,
        redirect: "error",
        signal: requestSignal,
      });
    } catch (error) {
      if (signal.aborted) {
        throw new Error("Login cancelled");
      }
      throw new Error("OpenAI token exchange failed. Start sign-in again.", { cause: error });
    }

    if (!response.ok) {
      const cancel = response.body?.cancel() ?? Promise.resolve();
      await withAbort(
        cancel.catch(() => undefined),
        requestSignal,
      ).catch(() => undefined);
      throw new Error(`OpenAI token exchange failed (${response.status}). Start sign-in again.`);
    }

    const body = await readTokenResponse(response, requestSignal);
    return parseOpenAiTokenExchangeResponse(body, {
      clientId: config.clientId,
      expectedNonce: nonce,
    });
  };
}

export async function refreshOpenAiChatGptOAuthToken(
  credential: OAuthCredential,
  signal?: AbortSignal,
  options: OpenAiChatGptOAuthOptions = {},
): Promise<OAuthCredential> {
  const request = options.fetch ?? fetch;
  const env = options.env ?? process.env;
  const storedClientId =
    typeof credential.clientId === "string" && credential.clientId.trim().length > 0
      ? credential.clientId.trim()
      : undefined;
  const clientId = (
    options.clientId ??
    storedClientId ??
    env[OPENAI_OAUTH_CLIENT_ID_ENV] ??
    ""
  ).trim();
  if (!clientId) {
    throw new Error(
      "OpenAI OAuth client ID is not configured. Set OPENAI_OAUTH_CLIENT_ID to refresh this credential.",
    );
  }
  const clientSecret = (options.clientSecret ?? env[OPENAI_OAUTH_CLIENT_SECRET_ENV] ?? "").trim();
  const callerSignal = signal ?? new AbortController().signal;
  const requestSignal = AbortSignal.any([callerSignal, AbortSignal.timeout(30_000)]);

  const params = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: credential.refresh,
  });
  if (clientSecret) {
    params.set("client_secret", clientSecret);
  }

  let response: Response;
  try {
    response = await request(OPENAI_TOKEN_URL, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: params,
      redirect: "error",
      signal: requestSignal,
    });
  } catch (error) {
    throw new Error("OpenAI token refresh failed.", { cause: error });
  }

  if (!response.ok) {
    const cancel = response.body?.cancel() ?? Promise.resolve();
    await withAbort(
      cancel.catch(() => undefined),
      requestSignal,
    ).catch(() => undefined);
    throw new Error(`OpenAI token refresh failed (${response.status}).`);
  }

  const body = await readTokenResponse(response, requestSignal);
  return parseOpenAiTokenRefreshResponse(body, credential, clientId);
}

function parseOpenAiTokenExchangeResponse(
  body: unknown,
  options: { clientId: string; expectedNonce: string },
): OAuthCredential {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("OpenAI token exchange returned an invalid credential.");
  }
  const token = body as {
    access_token?: unknown;
    refresh_token?: unknown;
    expires_in?: unknown;
    id_token?: unknown;
  };
  if (
    typeof token.access_token !== "string" ||
    token.access_token.trim().length === 0 ||
    typeof token.refresh_token !== "string" ||
    token.refresh_token.trim().length === 0 ||
    typeof token.expires_in !== "number" ||
    !Number.isFinite(token.expires_in) ||
    token.expires_in <= 0
  ) {
    throw new Error("OpenAI token exchange returned an invalid credential.");
  }

  if (typeof token.id_token !== "string" || token.id_token.trim().length === 0) {
    throw new Error("OpenAI token exchange did not include an ID token.");
  }
  const idClaims = validateOpenAiIdTokenClaims(token.id_token, options);
  const accountId =
    extractAccountIdFromJwtPayload(decodeJwtPayload(token.access_token)) ??
    extractAccountIdFromJwtPayload(idClaims);

  return {
    type: "oauth",
    access: token.access_token,
    refresh: token.refresh_token,
    expires: Date.now() + token.expires_in * 1000 - EXPIRY_MARGIN_MS,
    ...(accountId ? { accountId } : {}),
    clientId: options.clientId,
    oauthFlow: "siwc",
  };
}

function parseOpenAiTokenRefreshResponse(
  body: unknown,
  previous: OAuthCredential,
  clientId: string,
): OAuthCredential {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("OpenAI token refresh returned an invalid credential.");
  }
  const token = body as {
    access_token?: unknown;
    refresh_token?: unknown;
    expires_in?: unknown;
    id_token?: unknown;
  };
  const refreshToken =
    typeof token.refresh_token === "string" && token.refresh_token.trim().length > 0
      ? token.refresh_token
      : previous.refresh;
  if (
    typeof token.access_token !== "string" ||
    token.access_token.trim().length === 0 ||
    typeof refreshToken !== "string" ||
    refreshToken.trim().length === 0 ||
    typeof token.expires_in !== "number" ||
    !Number.isFinite(token.expires_in) ||
    token.expires_in <= 0
  ) {
    throw new Error("OpenAI token refresh returned an invalid credential.");
  }

  const previousAccountId =
    typeof previous.accountId === "string" && previous.accountId.trim().length > 0
      ? previous.accountId.trim()
      : undefined;
  const nextAccountId =
    extractAccountIdFromJwtPayload(decodeJwtPayload(token.access_token)) ??
    (typeof token.id_token === "string"
      ? extractAccountIdFromJwtPayload(decodeJwtPayload(token.id_token))
      : undefined) ??
    previousAccountId;

  return {
    type: "oauth",
    access: token.access_token,
    refresh: refreshToken,
    expires: Date.now() + token.expires_in * 1000 - EXPIRY_MARGIN_MS,
    ...(nextAccountId ? { accountId: nextAccountId } : {}),
    clientId,
    oauthFlow: "siwc",
  };
}

function validateOpenAiIdTokenClaims(
  idToken: string,
  options: { clientId: string; expectedNonce: string },
): Record<string, unknown> {
  const payload = decodeJwtPayload(idToken);
  if (!payload) {
    throw new Error("OpenAI token exchange returned an invalid ID token.");
  }
  const nonce = payload.nonce;
  if (
    typeof nonce !== "string" ||
    !nonce ||
    !timingSafeEqualStrings(nonce, options.expectedNonce)
  ) {
    throw new Error("OpenAI OAuth ID token nonce mismatch.");
  }
  const issuer = payload.iss;
  if (
    typeof issuer !== "string" ||
    (issuer !== OPENAI_OAUTH_ISSUER && issuer !== `${OPENAI_OAUTH_ISSUER}/`)
  ) {
    throw new Error("OpenAI OAuth ID token issuer mismatch.");
  }
  const audience = payload.aud;
  const matchesAudience =
    (typeof audience === "string" && audience === options.clientId) ||
    (Array.isArray(audience) && audience.includes(options.clientId));
  if (!matchesAudience) {
    throw new Error("OpenAI OAuth ID token audience mismatch.");
  }
  const exp = payload.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp) || exp * 1000 <= Date.now()) {
    throw new Error("OpenAI OAuth ID token has expired.");
  }
  return payload;
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3 || !parts[1]) return null;
    const decoded = Buffer.from(parts[1], "base64url").toString("utf8");
    const parsed = JSON.parse(decoded) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function extractAccountIdFromJwtPayload(
  payload: Record<string, unknown> | null,
): string | undefined {
  if (!payload) return undefined;
  const authClaim = payload[JWT_AUTH_CLAIM_PATH];
  if (authClaim && typeof authClaim === "object" && !Array.isArray(authClaim)) {
    const claimAccountId = (authClaim as Record<string, unknown>).chatgpt_account_id;
    if (typeof claimAccountId === "string" && claimAccountId.trim().length > 0) {
      return claimAccountId.trim();
    }
  }
  const topLevelAccountId = payload.chatgpt_account_id;
  if (typeof topLevelAccountId === "string" && topLevelAccountId.trim().length > 0) {
    return topLevelAccountId.trim();
  }
  const subject = payload.sub;
  if (typeof subject === "string" && subject.trim().length > 0) {
    return subject.trim();
  }
  return undefined;
}

async function readTokenResponse(response: Response, signal: AbortSignal): Promise<unknown> {
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > MAX_OPENAI_TOKEN_RESPONSE_BYTES) {
    const cancel = response.body?.cancel() ?? Promise.resolve();
    await withAbort(
      cancel.catch(() => undefined),
      signal,
    ).catch(() => undefined);
    throw new Error("OpenAI token exchange response is too large.");
  }
  try {
    const bytes = await readBodyCapped(response, MAX_OPENAI_TOKEN_RESPONSE_BYTES, signal);
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch (error) {
    if (error instanceof Error && error.message === "Response is too large") {
      throw new Error("OpenAI token exchange response is too large.");
    }
    throw new Error("OpenAI token exchange returned invalid JSON.");
  }
}

function sanitizeOAuthErrorCode(rawError: string): string {
  const cleaned = rawError.trim().replace(/[^a-zA-Z0-9._:-]/g, "");
  return cleaned.slice(0, 64) || "authorization_error";
}

export function parseOpenAiAuthorizationInput(
  input: string,
  expectedRedirectUri?: string,
): { code?: string; state?: string } {
  const value = input.trim();
  if (!value) return {};

  if (value.startsWith("http://") || value.startsWith("https://")) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new Error("Invalid OAuth callback URL.");
    }
    if (expectedRedirectUri) {
      const expected = new URL(expectedRedirectUri);
      if (url.origin !== expected.origin || url.pathname !== expected.pathname) {
        throw new Error("OAuth callback URL does not match the configured redirect URI.");
      }
    }
    const error = url.searchParams.get("error");
    if (error) {
      throw new Error(`ChatGPT authorization failed: ${sanitizeOAuthErrorCode(error)}`);
    }
    return {
      code: url.searchParams.get("code")?.trim() || undefined,
      state: url.searchParams.get("state")?.trim() || undefined,
    };
  }

  if (value.includes("#")) {
    const [code, state] = value.split("#", 2);
    return {
      code: code?.trim() || undefined,
      state: state?.trim() || undefined,
    };
  }

  if (value.includes("code=") || value.includes("state=") || value.includes("error=")) {
    const params = new URLSearchParams(value.startsWith("?") ? value.slice(1) : value);
    const error = params.get("error");
    if (error) {
      throw new Error(`ChatGPT authorization failed: ${sanitizeOAuthErrorCode(error)}`);
    }
    return {
      code: params.get("code")?.trim() || undefined,
      state: params.get("state")?.trim() || undefined,
    };
  }

  return { code: value };
}
