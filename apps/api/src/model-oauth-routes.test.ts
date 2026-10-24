import type { OAuthCredential } from "@earendil-works/pi-ai";
import type { PiOAuthConnected } from "@rakazo/adapters";
import { CHATGPT_OAUTH_PROVIDER, PiOAuthLogins } from "@rakazo/adapters";
import type { Actor } from "@rakazo/contracts";
import { Hono } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  mountModelOAuthRoutes,
  OPENAI_CODEX_OAUTH_CALLBACK_PATH,
  OPENAI_CODEX_OAUTH_START_PATH,
  resolveOpenAiCallbackRedirectUri,
} from "./model-oauth-routes.js";

function extractCookieHeader(setCookieHeader: string | null): string {
  if (!setCookieHeader) return "";
  return setCookieHeader.split(";")[0] ?? "";
}

function makeFakeOAuthCredential(overrides: Partial<OAuthCredential> = {}): OAuthCredential {
  return {
    type: "oauth",
    access: "access-placeholder",
    refresh: "refresh-placeholder",
    expires: Date.now() + 3_600_000,
    accountId: "acct-placeholder",
    clientId: "client-placeholder",
    oauthFlow: "siwc",
    ...overrides,
  };
}

describe("resolveOpenAiCallbackRedirectUri", () => {
  it("resolves HTTPS callbacks across Tailscale Serve and reverse proxies", () => {
    const request = new Request("http://127.0.0.1:3100/api/oauth/openai-codex/start", {
      headers: {
        "x-forwarded-proto": "https",
        "x-forwarded-host": "rakazo-vm.tailnet-example.ts.net",
      },
    });
    expect(
      resolveOpenAiCallbackRedirectUri({
        request,
        webOrigin: "http://127.0.0.1:5173",
        env: {},
      }),
    ).toBe(`https://rakazo-vm.tailnet-example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}`);
  });

  it("prefers explicit OPENAI_OAUTH_REDIRECT_URI when configured", () => {
    expect(
      resolveOpenAiCallbackRedirectUri({
        webOrigin: "https://other.example.com",
        env: {
          OPENAI_OAUTH_REDIRECT_URI: "https://custom.example.com/api/oauth/openai-codex/callback",
        },
      }),
    ).toBe("https://custom.example.com/api/oauth/openai-codex/callback");
  });
});

describe("mountModelOAuthRoutes", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
  });

  function createTestHarness(options?: {
    currentUser?: { id: string; email: string } | null;
    allowedSpaces?: Set<string>;
    oauthLogins?: PiOAuthLogins;
  }) {
    let currentUser =
      options?.currentUser === undefined
        ? { id: "user-1", email: "user1@example.test" }
        : options.currentUser;
    const allowedSpaces = options?.allowedSpaces ?? new Set(["user-1:space-1"]);
    const persisted: Array<{
      actor: Actor;
      login: PiOAuthConnected;
    }> = [];
    let stateCounter = 0;

    const oauthLogins =
      options?.oauthLogins ??
      new PiOAuthLogins(async (_provider, _type, interaction) => {
        stateCounter += 1;
        const state = `state-token-${stateCounter}`;
        interaction.notify({
          type: "auth_url",
          url: `https://auth.openai.com/api/accounts/authorize?response_type=code&client_id=client-placeholder&redirect_uri=${encodeURIComponent("https://rakazo.example.ts.net/api/oauth/openai-codex/callback")}&state=${state}&code_challenge=challenge-${stateCounter}&code_challenge_method=S256`,
        });
        const callbackUrl = await interaction.prompt({
          type: "manual_code",
          message: "Paste the callback URL or authorization code",
        });
        if (callbackUrl.includes("code=exchange-fail")) {
          throw new Error("OpenAI OAuth token exchange failed (HTTP 400).");
        }
        return makeFakeOAuthCredential({ access: `access-for-${state}` });
      });

    const app = new Hono();
    mountModelOAuthRoutes(app, {
      oauthLogins,
      authSecret: "test-signing-secret-placeholder-32chars",
      webOrigin: "https://rakazo.example.ts.net",
      authenticate: async (_req, spaceIdOverride) => {
        if (!currentUser) return { actor: null, authenticatedUser: false };
        const spaceId = spaceIdOverride ?? "space-1";
        if (!allowedSpaces.has(`${currentUser.id}:${spaceId}`)) {
          return { actor: null, authenticatedUser: true };
        }
        return {
          authenticatedUser: true,
          actor: {
            userId: currentUser.id,
            email: currentUser.email,
            spaceId,
            role: "owner",
          },
        };
      },
      persistOAuthCredential: async (actor, login) => {
        persisted.push({ actor, login });
        return {
          id: "cred-1",
          provider: CHATGPT_OAUTH_PROVIDER,
          label: "ChatGPT",
          hasKey: false,
          authKind: "oauth",
          isDefault: true,
          modelId: login.modelId ?? "gpt-5.3-codex",
        };
      },
    });

    return {
      app,
      oauthLogins,
      persisted,
      setCurrentUser(user: { id: string; email: string } | null) {
        currentUser = user;
      },
    };
  }

  it("returns a clear error when OPENAI_OAUTH_CLIENT_ID is not configured", async () => {
    vi.stubEnv("OPENAI_OAUTH_CLIENT_ID", "");
    const { app } = createTestHarness({
      oauthLogins: new PiOAuthLogins(),
    });

    const res = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=space-1&format=json`,
    );
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toEqual({
      error:
        "OpenAI OAuth client ID is not configured. Set OPENAI_OAUTH_CLIENT_ID or sign in with a device code.",
    });
  });

  it("rejects open-redirect parameters on start and callback", async () => {
    const { app } = createTestHarness();

    const startRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=space-1&redirect_to=https://evil.example.com`,
    );
    expect(startRes.status).toBe(400);

    const callbackRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=abc&state=xyz&return_to=https://evil.example.com`,
    );
    expect(callbackRes.status).toBe(400);
  });

  it("completes the full start -> callback flow and stores the credential once", async () => {
    const { app, persisted, oauthLogins } = createTestHarness();

    const startRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=space-1&modelId=gpt-5.3-codex&format=json`,
      {
        headers: {
          "x-forwarded-proto": "https",
          "x-forwarded-host": "rakazo.example.ts.net",
        },
      },
    );
    expect(startRes.status).toBe(200);
    expect(startRes.headers.get("cache-control")).toBe("no-store");
    expect(startRes.headers.get("referrer-policy")).toBe("no-referrer");
    const setCookie = startRes.headers.get("set-cookie");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
    expect(setCookie).toContain("Secure");

    const started = (await startRes.json()) as {
      loginId: string;
      verificationUri: string;
      mode: string;
    };
    expect(started.mode).toBe("auth-url");
    const state = new URL(started.verificationUri).searchParams.get("state");
    expect(state).toBe("state-token-1");

    const cookie = extractCookieHeader(setCookie);
    const callbackRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=${state}`,
      {
        headers: { cookie },
      },
    );
    expect(callbackRes.status).toBe(200);
    expect(callbackRes.headers.get("cache-control")).toBe("no-store");
    expect(callbackRes.headers.get("referrer-policy")).toBe("no-referrer");
    expect(persisted).toHaveLength(1);
    expect(persisted[0]?.actor).toMatchObject({
      userId: "user-1",
      spaceId: "space-1",
    });

    // finishOAuth via RPC after callback does not persist a duplicate record.
    const finishAgain = vi.fn(async () => "saved");
    await oauthLogins.finish(
      started.loginId,
      { userId: "user-1", spaceId: "space-1" },
      finishAgain,
    );
    expect(finishAgain).not.toHaveBeenCalled();

    // Replaying the same callback fails closed.
    const replayRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=${state}`,
      {
        headers: { cookie },
      },
    );
    expect(replayRes.status).toBe(409);
    expect(await replayRes.text()).toContain("OAuth callback has already been used.");
    expect(persisted).toHaveLength(1);
  });

  it("blocks CSRF, invalid cookie, mismatched state, and cross-user account mixing", async () => {
    const { app, persisted, setCurrentUser } = createTestHarness({
      allowedSpaces: new Set(["user-1:space-1", "user-2:space-1"]),
    });

    const startRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=space-1&format=json`,
    );
    const cookie = extractCookieHeader(startRes.headers.get("set-cookie"));
    const started = (await startRes.json()) as { verificationUri: string };
    const state = new URL(started.verificationUri).searchParams.get("state")!;

    // 1. Tampered state-binding cookie.
    const tamperedCookieRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=${state}`,
      { headers: { cookie: `${cookie}tampered` } },
    );
    expect(tamperedCookieRes.status).toBe(403);
    expect(await tamperedCookieRes.text()).toContain(
      "OAuth callback cookie is invalid or expired.",
    );

    // 2. Mismatched state parameter against cookie.
    const wrongStateRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=wrong-state`,
      { headers: { cookie } },
    );
    expect(wrongStateRes.status).toBe(403);
    expect(await wrongStateRes.text()).toContain(
      "OAuth callback does not match the active browser session.",
    );

    // 3. Unknown state without cookie.
    const unknownStateRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=unknown-state`,
    );
    expect(unknownStateRes.status).toBe(400);
    expect(await unknownStateRes.text()).toContain("Invalid OAuth state.");

    // 4. Cross-user account mixing (cookie from user-1 replayed while logged in as user-2).
    setCurrentUser({ id: "user-2", email: "user2@example.test" });
    const mixedUserRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=${state}`,
      { headers: { cookie } },
    );
    expect(mixedUserRes.status).toBe(403);
    expect(await mixedUserRes.text()).toContain(
      "OAuth callback does not match the active browser session.",
    );
    expect(persisted).toHaveLength(0);
  });

  it("handles user cancellation, expired state, and token exchange failure", async () => {
    vi.useFakeTimers();
    const { app, persisted } = createTestHarness();

    // 1. User cancellation at provider.
    const startCancel = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=space-1&format=json`,
    );
    const cookieCancel = extractCookieHeader(startCancel.headers.get("set-cookie"));
    const stateCancel = new URL(
      ((await startCancel.json()) as { verificationUri: string }).verificationUri,
    ).searchParams.get("state")!;
    const cancelRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?error=access_denied&state=${stateCancel}`,
      { headers: { cookie: cookieCancel } },
    );
    expect(cancelRes.status).toBe(400);
    expect(await cancelRes.text()).toContain("ChatGPT sign-in was cancelled or denied.");

    // 2. Expired state.
    const startExpired = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=space-1&format=json`,
    );
    const stateExpired = new URL(
      ((await startExpired.json()) as { verificationUri: string }).verificationUri,
    ).searchParams.get("state")!;
    vi.advanceTimersByTime(601_000);
    const expiredRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=${stateExpired}`,
    );
    expect(expiredRes.status).toBe(410);
    expect(await expiredRes.text()).toContain("OAuth state has expired.");

    // 3. Token exchange failure.
    const startFail = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=space-1&format=json`,
    );
    const cookieFail = extractCookieHeader(startFail.headers.get("set-cookie"));
    const stateFail = new URL(
      ((await startFail.json()) as { verificationUri: string }).verificationUri,
    ).searchParams.get("state")!;
    const failRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=exchange-fail&state=${stateFail}`,
      { headers: { cookie: cookieFail } },
    );
    expect(failRes.status).toBe(502);
    expect(await failRes.text()).toContain("OpenAI OAuth token exchange failed (HTTP 400).");
    expect(persisted).toHaveLength(0);
  });
});
