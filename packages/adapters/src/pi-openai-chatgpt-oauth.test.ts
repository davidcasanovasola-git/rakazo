import { createHash } from "node:crypto";
import type { AuthInteraction } from "@earendil-works/pi-ai";
import { describe, expect, it, vi } from "vitest";
import {
  createOpenAiChatGptOAuthLogin,
  OPENAI_AUTHORIZE_URL,
  OPENAI_OAUTH_ISSUER,
  OPENAI_OAUTH_SCOPES,
  OPENAI_TOKEN_URL,
  openAiOAuthConfigFromEnv,
  parseOpenAiAuthorizationInput,
  refreshOpenAiChatGptOAuthToken,
  validateOpenAiRedirectUri,
} from "./pi-openai-chatgpt-oauth.js";

function makeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.signature`;
}

describe("OpenAI ChatGPT OAuth (SIWC Authorization Code + PKCE)", () => {
  it("detects missing OPENAI_OAUTH_CLIENT_ID with a clear error", () => {
    expect(() => openAiOAuthConfigFromEnv({})).toThrow(
      "OpenAI OAuth client ID is not configured. Set OPENAI_OAUTH_CLIENT_ID or sign in with a device code.",
    );
  });

  it("validates redirect URIs against open-redirect and insecure HTTP hosts", () => {
    expect(
      validateOpenAiRedirectUri("https://rakazo.example.ts.net/api/oauth/openai-codex/callback"),
    ).toBe("https://rakazo.example.ts.net/api/oauth/openai-codex/callback");
    expect(validateOpenAiRedirectUri("http://localhost:1455/auth/callback")).toBe(
      "http://localhost:1455/auth/callback",
    );
    expect(() => validateOpenAiRedirectUri("http://remote.example.com/callback")).toThrow(
      /must use HTTPS or localhost HTTP/,
    );
    expect(() => validateOpenAiRedirectUri("https://user:pass@example.com/callback")).toThrow(
      /must use HTTPS or localhost HTTP without query or hash parameters/,
    );
    expect(() => validateOpenAiRedirectUri("https://example.com/callback?foo=bar")).toThrow(
      /must use HTTPS or localhost HTTP without query or hash parameters/,
    );
  });

  it("builds the official OpenAI authorization URL with RFC 7636 S256 PKCE, state, and nonce", async () => {
    const randomValues = ["verifier-value-1234567890", "state-value-123", "nonce-value-456"];
    let notifiedUrl = "";
    const login = createOpenAiChatGptOAuthLogin({
      clientId: "client-placeholder",
      redirectUri: "https://app.example.com/api/oauth/openai-codex/callback",
      createRandomValue: () => randomValues.shift() ?? "fallback",
      fetch: async () =>
        Response.json({
          access_token: "access-token-placeholder",
          refresh_token: "refresh-token-placeholder",
          id_token: makeJwt({
            iss: OPENAI_OAUTH_ISSUER,
            aud: "client-placeholder",
            nonce: "nonce-value-456",
            exp: Math.floor(Date.now() / 1000) + 3600,
          }),
          expires_in: 3600,
        }),
    });

    const interaction: AuthInteraction = {
      signal: new AbortController().signal,
      notify(event) {
        if (event.type === "auth_url") {
          notifiedUrl = event.url;
        }
      },
      async prompt() {
        return "https://app.example.com/api/oauth/openai-codex/callback?code=code-abc&state=state-value-123";
      },
    };

    await login(interaction);

    const url = new URL(notifiedUrl);
    const expectedChallenge = createHash("sha256")
      .update("verifier-value-1234567890")
      .digest("base64url");
    expect(`${url.origin}${url.pathname}`).toBe(OPENAI_AUTHORIZE_URL);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("client-placeholder");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "https://app.example.com/api/oauth/openai-codex/callback",
    );
    expect(url.searchParams.get("scope")).toBe(OPENAI_OAUTH_SCOPES);
    expect(url.searchParams.get("state")).toBe("state-value-123");
    expect(url.searchParams.get("code_challenge")).toBe(expectedChallenge);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("nonce")).toBe("nonce-value-456");
  });

  it("parses callback URLs, query strings, and provider error responses safely", () => {
    expect(
      parseOpenAiAuthorizationInput(
        "http://localhost:1455/auth/callback?code=auth-code-123&state=state-abc",
        "http://localhost:1455/auth/callback",
      ),
    ).toEqual({
      code: "auth-code-123",
      state: "state-abc",
    });

    expect(() =>
      parseOpenAiAuthorizationInput(
        "https://evil.example.com/callback?code=auth-code-123&state=state-abc",
        "https://app.example.com/api/oauth/openai-codex/callback",
      ),
    ).toThrow(/OAuth callback URL does not match the configured redirect URI/);

    expect(() =>
      parseOpenAiAuthorizationInput(
        "http://localhost:1455/auth/callback?error=access_denied",
        "http://localhost:1455/auth/callback",
      ),
    ).toThrow("ChatGPT authorization failed: access_denied");
  });

  it("completes the authorization code flow, validates state/nonce/ID token, and returns an OAuth credential", async () => {
    let notifiedUrl = "";
    let capturedNonce = "";
    let capturedState = "";
    const interaction: AuthInteraction = {
      signal: new AbortController().signal,
      notify(event) {
        if (event.type === "auth_url") {
          notifiedUrl = event.url;
          const parsed = new URL(event.url);
          capturedNonce = parsed.searchParams.get("nonce") ?? "";
          capturedState = parsed.searchParams.get("state") ?? "";
        }
      },
      async prompt() {
        return `https://app.example.com/api/oauth/openai-codex/callback?code=code-xyz&state=${capturedState}`;
      },
    };

    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toBe(OPENAI_TOKEN_URL);
      const body = new URLSearchParams(String(init?.body ?? ""));
      expect(body.get("grant_type")).toBe("authorization_code");
      expect(body.get("client_id")).toBe("client-placeholder");
      expect(body.get("code")).toBe("code-xyz");
      expect(body.get("redirect_uri")).toBe(
        "https://app.example.com/api/oauth/openai-codex/callback",
      );
      expect(body.get("code_verifier")?.length).toBeGreaterThanOrEqual(43);

      const idToken = makeJwt({
        iss: OPENAI_OAUTH_ISSUER,
        aud: "client-placeholder",
        nonce: capturedNonce,
        exp: Math.floor(Date.now() / 1000) + 3600,
        "https://api.openai.com/auth": {
          chatgpt_account_id: "acct_placeholder",
        },
      });
      return Response.json({
        access_token: "access-token-placeholder",
        refresh_token: "refresh-token-placeholder",
        id_token: idToken,
        expires_in: 3600,
      });
    });

    const login = createOpenAiChatGptOAuthLogin({
      clientId: "client-placeholder",
      redirectUri: "https://app.example.com/api/oauth/openai-codex/callback",
      fetch: fetchImpl,
    });
    const credential = await login(interaction);

    expect(notifiedUrl).toContain(OPENAI_AUTHORIZE_URL);
    expect(credential).toMatchObject({
      type: "oauth",
      access: "access-token-placeholder",
      refresh: "refresh-token-placeholder",
      accountId: "acct_placeholder",
      clientId: "client-placeholder",
      oauthFlow: "siwc",
    });
  });

  it("rejects mismatched state, bare code without state, and missing or invalid ID token claims", async () => {
    let capturedState = "";
    let capturedNonce = "";
    let promptMessage = "";
    const interactionBareCode: AuthInteraction = {
      signal: new AbortController().signal,
      notify() {},
      async prompt(req) {
        promptMessage = req.message;
        return "bare-authorization-code-only";
      },
    };

    const loginMismatch = createOpenAiChatGptOAuthLogin({
      clientId: "client-placeholder",
      redirectUri: "https://app.example.com/api/oauth/openai-codex/callback",
    });
    await expect(loginMismatch(interactionBareCode)).rejects.toThrow("Missing OAuth state.");
    expect(promptMessage).toBe("Complete sign-in in your browser, or paste the callback URL:");

    const interactionMismatchState: AuthInteraction = {
      signal: new AbortController().signal,
      notify(event) {
        if (event.type === "auth_url") {
          capturedState = new URL(event.url).searchParams.get("state") ?? "";
        }
      },
      async prompt() {
        return `https://app.example.com/api/oauth/openai-codex/callback?code=code-xyz&state=${capturedState}-tampered`;
      },
    };

    await expect(loginMismatch(interactionMismatchState)).rejects.toThrow("OAuth state mismatch.");

    const makeValidPromptInteraction = (): AuthInteraction => ({
      signal: new AbortController().signal,
      notify(event) {
        if (event.type === "auth_url") {
          const parsed = new URL(event.url);
          capturedState = parsed.searchParams.get("state") ?? "";
          capturedNonce = parsed.searchParams.get("nonce") ?? "";
        }
      },
      async prompt() {
        return `https://app.example.com/api/oauth/openai-codex/callback?code=code-xyz&state=${capturedState}`;
      },
    });

    const loginWithClaims = (claimsBuilder: (nonce: string) => Record<string, unknown>) =>
      createOpenAiChatGptOAuthLogin({
        clientId: "client-placeholder",
        redirectUri: "https://app.example.com/api/oauth/openai-codex/callback",
        fetch: async () =>
          Response.json({
            access_token: "access-placeholder",
            refresh_token: "refresh-placeholder",
            id_token: makeJwt(claimsBuilder(capturedNonce)),
            expires_in: 3600,
          }),
      });

    await expect(
      loginWithClaims(() => ({
        iss: OPENAI_OAUTH_ISSUER,
        aud: "client-placeholder",
        nonce: "wrong-nonce",
        exp: Math.floor(Date.now() / 1000) + 3600,
      }))(makeValidPromptInteraction()),
    ).rejects.toThrow(/nonce mismatch/);

    await expect(
      loginWithClaims((nonce) => ({
        aud: "client-placeholder",
        nonce,
        exp: Math.floor(Date.now() / 1000) + 3600,
      }))(makeValidPromptInteraction()),
    ).rejects.toThrow(/issuer mismatch/);

    await expect(
      loginWithClaims((nonce) => ({
        iss: OPENAI_OAUTH_ISSUER,
        nonce,
        exp: Math.floor(Date.now() / 1000) + 3600,
      }))(makeValidPromptInteraction()),
    ).rejects.toThrow(/audience mismatch/);

    await expect(
      loginWithClaims((nonce) => ({
        iss: OPENAI_OAUTH_ISSUER,
        aud: "client-placeholder",
        nonce,
      }))(makeValidPromptInteraction()),
    ).rejects.toThrow(/ID token has expired/);
  });

  it("refreshes an SIWC OAuth token using the stored clientId", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toBe(OPENAI_TOKEN_URL);
      const body = new URLSearchParams(String(init?.body ?? ""));
      expect(body.get("grant_type")).toBe("refresh_token");
      expect(body.get("refresh_token")).toBe("old-refresh");
      expect(body.get("client_id")).toBe("stored-client-id");
      return Response.json({
        access_token: "new-access",
        refresh_token: "new-refresh",
        expires_in: 3600,
      });
    });

    const refreshed = await refreshOpenAiChatGptOAuthToken(
      {
        type: "oauth",
        access: "old-access",
        refresh: "old-refresh",
        expires: Date.now() - 1000,
        accountId: "acct_1",
        clientId: "stored-client-id",
        oauthFlow: "siwc",
      },
      undefined,
      { env: {}, fetch: fetchImpl },
    );

    expect(refreshed).toMatchObject({
      type: "oauth",
      access: "new-access",
      refresh: "new-refresh",
      accountId: "acct_1",
      clientId: "stored-client-id",
      oauthFlow: "siwc",
    });
  });
});
