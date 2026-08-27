import raw from "./ledger.json";
import type { LedgerData } from "./types";

const ledger = raw as unknown as Partial<LedgerData>;

export default { ...ledger, articles: ledger.articles ?? [] } as LedgerData;
