import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

const site = process.env.ASI_PUBLICATION_DOMAIN ?? "https://agentic-security-intelligence.pages.dev";
const siteUrl = new URL(site);
if (
  siteUrl.protocol !== "https:" ||
  siteUrl.username ||
  siteUrl.password ||
  siteUrl.search ||
  siteUrl.hash ||
  siteUrl.pathname !== "/"
) {
  throw new Error("ASI_PUBLICATION_DOMAIN must be an HTTPS origin");
}

export default defineConfig({
  output: "static",
  site: siteUrl.origin,
  integrations: [sitemap()],
});
