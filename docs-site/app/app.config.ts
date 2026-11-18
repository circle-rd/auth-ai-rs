export default defineAppConfig({
  ui: {
    colors: {
      primary: "neutral",
    },
  },
  seo: {
    title: "CIRCLE auth-ai (Rust)",
    description:
      "Rust SDK for applications relying on a CIRCLE auth-service identity provider: backend-for-frontend OIDC sign-in, entitlements, billing, credit wallet and LiteLLM gateway.",
  },
  header: {
    title: "CIRCLE auth-ai (Rust)",
    logo: {
      light: "/logo-light.svg",
      dark: "/logo-dark.svg",
      alt: "CIRCLE",
    },
  },
  socials: {
    github: "https://github.com/circle-rd/auth-ai-rs",
  },
  github: {
    url: "https://github.com/circle-rd/auth-ai-rs",
    branch: "main",
    rootDir: "docs-site",
  },
});
