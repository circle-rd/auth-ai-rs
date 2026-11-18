export default defineNuxtConfig({
  extends: ["docus"],
  css: ["~/circle-theme.css"],
  fonts: {
    families: [
      {
        name: "Lato",
        provider: "google",
        weights: [100, 300, 400, 700],
      },
    ],
  },
  app: {
    baseURL: process.env.NUXT_APP_BASE_URL ?? "/auth-ai/rust/",
  },
  site: {
    url: process.env.NUXT_SITE_URL ?? "https://docs.circle-cyber.com/auth-ai/rust",
    name: "CIRCLE auth-ai (Rust)",
  },
  robots: { robotsTxt: false },
  image: {
    provider: "passthrough",
    providers: {
      passthrough: { name: "passthrough", provider: "~/providers/passthrough" },
    },
  },
  meta: {
    title: "CIRCLE auth-ai (Rust)",
    description:
      "Rust SDK for applications relying on a CIRCLE auth-service identity provider: OIDC sign-in (backend-for-frontend), entitlements, billing, credit wallet and LiteLLM gateway.",
    ogHost:
      process.env.NUXT_SITE_URL ?? "https://docs.circle-cyber.com/auth-ai/rust",
  },
  llms: {
    title: "CIRCLE auth-ai (Rust)",
    description:
      "Rust SDK (auth-ai on crates.io, imported as auth_ai) for applications relying on a CIRCLE auth-service identity provider: OIDC sign-in (backend-for-frontend), entitlements, billing, credit wallet and LiteLLM gateway.",
    full: {
      title: "CIRCLE auth-ai (Rust) — Complete Documentation",
      description:
        "Complete documentation for auth-ai, the Rust SDK for applications that sign users in through a CIRCLE auth-service. Covers the async OIDC client, the backend-for-frontend sign-in handlers with the axum adapter, bearer token verification, back-channel logout, the credit wallet, the LiteLLM gateway client, billing and consumption, resource sharing, configuration and the error code registry.",
    },
    sections: [
      {
        title: "Developer Resources",
        description: "Machine-readable entry points for this project.",
        links: [
          {
            title: "CIRCLE auth-ai (Rust) on GitHub",
            description: "Source, issues and releases of the Rust SDK.",
            href: "https://github.com/circle-rd/auth-ai-rs",
          },
          {
            title: "CIRCLE auth-ai (TypeScript) documentation",
            description:
              "The TypeScript SDK this one is ported from, with the browser client and the React and Vue bindings.",
            href: "https://docs.circle-cyber.com/auth-ai/typescript/",
          },
          {
            title: "CIRCLE auth-ai (Python) documentation",
            description: "The Python SDK, the other port of the TypeScript SDK.",
            href: "https://docs.circle-cyber.com/auth-ai/python/",
          },
          {
            title: "CIRCLE auth-service documentation",
            description:
              "The identity provider this SDK talks to: applications, claims, wallet, LiteLLM gateway.",
            href: "https://docs.circle-cyber.com/auth-service/",
          },
        ],
      },
    ],
    notes: [
      "This is the Rust port of the TypeScript SDK @circle-rd/auth-ai (documented at https://docs.circle-cyber.com/auth-ai/typescript/) and a sibling of the Python SDK (https://docs.circle-cyber.com/auth-ai/python/). The three SDKs share the same wire contract: the backend-for-frontend routes, the sealed login cookie format, the cookie names and the error code registry.",
      "When to use CIRCLE auth-ai (Rust): in a Tokio-based Rust backend (axum, or another framework through the framework-agnostic WebRequest and WebResponse handlers) that signs users in through a CIRCLE auth-service instance (OIDC authorization code with PKCE, backend-for-frontend) and, optionally, reads the user's credit wallet and calls the LiteLLM gateway on the user's behalf.",
      "CIRCLE auth-ai is built for auth-service (its claims and its wallet, billing and consumption REST routes): it is not a client for arbitrary OIDC providers, and it is not an identity provider. To run the provider, use the auth-service documentation at https://docs.circle-cyber.com/auth-service/.",
      "Tokens stay on the server: the browser only holds an opaque session cookie. The SDK has no debit API: the gateway debits the wallet after each call.",
      "The crate is async only (Tokio, reqwest with rustls, aws-lc-rs for the cryptography), requires Rust 1.89 or later, forbids unsafe code, and is a 0.x release whose public API is not stable yet. The only web-framework adapter is axum, behind the optional `axum` feature.",
      "JWTs are verified against the single algorithm the provider advertises among ES256/384/512, RS256/384/512, PS256/384/512 and the fully specified Ed25519. EdDSA (deprecated by RFC 9864), HMAC and none are refused; Ed448 is not supported.",
      "The browser client and the React and Vue bindings are not part of this crate: pair the Rust backend with the TypeScript package @circle-rd/auth-ai, documented at https://docs.circle-cyber.com/auth-ai/typescript/.",
      "Reading this documentation as an agent: every page is also served as markdown under /raw/, for example https://docs.circle-cyber.com/auth-ai/rust/raw/docs/concepts/architecture.md. The full text is at https://docs.circle-cyber.com/auth-ai/rust/llms-full.txt and a page index at https://docs.circle-cyber.com/auth-ai/rust/llms.txt.",
    ],
  },
});
