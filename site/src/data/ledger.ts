import raw from "./ledger.json";
import type { LedgerData } from "./types";

export default ("articles" in raw ? raw : { ...raw, articles: [] }) as LedgerData;
