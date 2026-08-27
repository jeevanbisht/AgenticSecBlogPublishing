import data from "../data/ledger";

const escapeXml = (value) =>
  value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

export function GET(context) {
  const site = context.site.toString().replace(/\/$/, "");
  const entries = data.changes.map((change) => `
    <entry>
      <id>urn:asi:${change.id}</id>
      <title>${escapeXml(change.description)}</title>
      <updated>${change.date}T00:00:00Z</updated>
      <link href="${site}/changes/" />
      <summary>${escapeXml(`${change.classification}: ${change.decision_impacts.join(", ")}`)}</summary>
    </entry>`).join("");
  return new Response(`<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${site}/</id>
  <title>Agentic Security Intelligence</title>
  <updated>${data.generated_at}</updated>
  <link href="${site}/atom.xml" rel="self" />
  ${entries}
</feed>`, { headers: { "Content-Type": "application/atom+xml; charset=utf-8" } });
}
