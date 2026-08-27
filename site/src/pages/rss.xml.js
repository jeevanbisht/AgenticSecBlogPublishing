import rss from "@astrojs/rss";
import data from "../data/ledger";

export function GET(context) {
  return rss({
    title: "Agentic Security Intelligence",
    description: "Evidence-driven change intelligence for enterprise security agents.",
    site: context.site,
    items: data.changes.map((change) => ({
      title: change.description,
      pubDate: new Date(`${change.date}T00:00:00Z`),
      description: `${change.classification}: ${change.decision_impacts.join(", ")}`,
      link: "/changes/",
    })),
  });
}
