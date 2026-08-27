import raw from "./ledger.json";
import type { LedgerData } from "./types";

export default { articles: [], ...raw } as LedgerData;
