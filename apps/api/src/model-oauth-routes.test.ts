import { randomUUID } from "node:crypto";
import type { OAuthCredential } from "@earendil-works/pi-ai";
import type { PiOAuthConnected } from "@rakazo/adapters";
import { CHATGPT_OAUTH_PROVIDER, createSecretStore, PiOAuthLogins } from "@rakazo/adapters";
import type { Actor } from "@rakazo/contracts";
import type { DbContext } from "@rakazo/db";
import { asSystem, bootstrapUserSpace, createDb, currentDbContext, runAsSystem } from "@rakazo/db";
import { Hono } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createOpenAiOAuthBindingCookieHeader,
  mountModelOAuthRoutes,
  OPENAI_CODEX_OAUTH_CALLBACK_PATH,
  OPENAI_CODEX_OAUTH_START_PATH,
  resolveOpenAiCallbackRedirectUri,
} from "./model-oauth-routes.js";
import type { RouterDeps } from "./router.js";
import { persistOAuthLoginCredential } from "./router.js";

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
      dbContext: DbContext | undefined;
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
          message: "Complete sign-in in your browser, or paste the callback URL:",
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
        persisted.push({ actor, login, dbContext: currentDbContext() });
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
    const callbackHtml = await callbackRes.text();
    expect(callbackHtml).toContain("var(--background)");
    expect(callbackHtml).toContain("var(--foreground)");
    expect(callbackHtml).toContain("var(--muted-foreground)");
    expect(persisted).toHaveLength(1);
    expect(persisted[0]?.actor).toMatchObject({
      userId: "user-1",
      spaceId: "space-1",
    });
    expect(persisted[0]?.dbContext).toEqual({
      kind: "tenant",
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

  it("accepts a retry started via beginOAuth RPC even when an earlier HTTP binding cookie was set", async () => {
    const { app, oauthLogins, persisted } = createTestHarness();

    // 1. Start first attempt via HTTP start route (sets cookie for state-token-1).
    const firstStart = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=space-1&format=json`,
    );
    expect(firstStart.status).toBe(200);
    const staleCookie = extractCookieHeader(firstStart.headers.get("set-cookie"));

    // 2. Retry via oauthLogins.begin (as models.beginOAuth RPC does).
    const secondStarted = await oauthLogins.begin({
      userId: "user-1",
      spaceId: "space-1",
      provider: CHATGPT_OAUTH_PROVIDER,
      mode: "auth-url",
      redirectUri: "https://rakazo.example.ts.net/api/oauth/openai-codex/callback",
    });
    const secondState = new URL(secondStarted.verificationUri).searchParams.get("state")!;
    expect(secondState).toBe("state-token-2");

    // Updated cookie created by models.beginOAuth works, and even if the browser still had
    // staleCookie from the superseded attempt, the active session for the same user/space succeeds.
    const updatedCookieHeader = createOpenAiOAuthBindingCookieHeader({
      loginId: secondStarted.loginId,
      userId: "user-1",
      spaceId: "space-1",
      verificationUri: secondStarted.verificationUri,
      redirectUri: "https://rakazo.example.ts.net/api/oauth/openai-codex/callback",
      authSecret: "test-signing-secret-placeholder-32chars",
    });
    expect(updatedCookieHeader).toContain("rakazo_openai_oauth=");

    const callbackRes = await app.request(
      `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=${secondState}`,
      { headers: { cookie: staleCookie } },
    );
    expect(callbackRes.status).toBe(200);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]?.login.credential.access).toBe("access-for-state-token-2");
  });

  const databaseUrl = process.env.VERIFY_DATABASE === "1" ? process.env.DATABASE_URL : undefined;
  it.skipIf(!databaseUrl)(
    "persists the OAuth credential under tenant RLS scope during the HTTP callback",
    async () => {
      const db = createDb(databaseUrl!);
      const system = asSystem(db.prisma);
      const userId = randomUUID();
      let spaceId = "";
      try {
        await system.user.create({
          data: {
            id: userId,
            name: "OAuth RLS Tester",
            email: `oauth-rls-${userId}@example.test`,
            emailVerified: true,
          },
        });
        ({ spaceId } = await runAsSystem("oauth rls fixture", () =>
          bootstrapUserSpace(
            db.prisma,
            { id: userId },
            { signupsEnabled: "true", signupAllowlist: "" },
          ),
        ));

        const oauthLogins = new PiOAuthLogins(async (_provider, _type, interaction) => {
          interaction.notify({
            type: "auth_url",
            url: `https://auth.openai.com/api/accounts/authorize?response_type=code&client_id=client-placeholder&redirect_uri=${encodeURIComponent("https://rakazo.example.ts.net/api/oauth/openai-codex/callback")}&state=rls-state-1&code_challenge=challenge-1&code_challenge_method=S256`,
          });
          await interaction.prompt({
            type: "manual_code",
            message: "Complete sign-in in your browser, or paste the callback URL:",
          });
          return makeFakeOAuthCredential({ access: "rls-access-token" });
        });

        const secrets = createSecretStore({ masterKey: "ab".repeat(32) });
        const app = new Hono();
        mountModelOAuthRoutes(app, {
          oauthLogins,
          authSecret: "test-signing-secret-placeholder-32chars",
          webOrigin: "https://rakazo.example.ts.net",
          authenticate: async () => ({
            authenticatedUser: true,
            actor: {
              userId,
              email: `oauth-rls-${userId}@example.test`,
              spaceId,
              role: "owner",
            },
          }),
          persistOAuthCredential: (actor, login) =>
            persistOAuthLoginCredential(
              {
                prisma: db.prisma,
                secrets,
                oauthLogins,
                env: {
                  defaultProvider: CHATGPT_OAUTH_PROVIDER,
                  defaultModel: "gpt-5.3-codex",
                },
              } as unknown as RouterDeps,
              actor,
              login,
            ),
        });

        const startRes = await app.request(
          `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_START_PATH}?spaceId=${spaceId}&modelId=gpt-5.3-codex&format=json`,
        );
        expect(startRes.status).toBe(200);
        const cookie = extractCookieHeader(startRes.headers.get("set-cookie"));

        const callbackRes = await app.request(
          `https://rakazo.example.ts.net${OPENAI_CODEX_OAUTH_CALLBACK_PATH}?code=valid-code&state=rls-state-1&format=json`,
          { headers: { cookie } },
        );
        expect(callbackRes.status).toBe(200);
        const body = (await callbackRes.json()) as {
          ok: boolean;
          credential: { provider: string };
        };
        expect(body.ok).toBe(true);
        expect(body.credential.provider).toBe(CHATGPT_OAUTH_PROVIDER);
      } finally {
        if (spaceId) await system.organization.delete({ where: { id: spaceId } });
        await system.user.deleteMany({ where: { id: userId } });
        await db.prisma.$disconnect();
        await db.pool.end();
      }
    },
  );
});
