/** Official CISA KEV catalog validation; no network or persistence. */
export type KevRecord = Record<string, unknown> & { cveID: string; vendorProject: string; product: string; dateAdded: string };
export interface KevCatalog { catalogVersion: string; dateReleased: string; records: KevRecord[] }
const CVE = /^CVE-\d{4}-\d{4,}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const object = (v: unknown): Record<string, unknown> | null => v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null;
function validDate(value: unknown): value is string {
 if (typeof value !== 'string' || !DATE.test(value)) return false;
 const date = new Date(`${value}T00:00:00.000Z`);
 return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}
/** Reject malformed or duplicate records before any catalog is persisted. */
export function validateKevCatalog(input: unknown): KevCatalog {
 const catalog=object(input);
 if (!catalog || typeof catalog.catalogVersion !== 'string' || !catalog.catalogVersion.trim() || typeof catalog.dateReleased !== 'string' || !Number.isFinite(Date.parse(catalog.dateReleased)) || !Number.isSafeInteger(catalog.count) || !Array.isArray(catalog.vulnerabilities) || catalog.vulnerabilities.length===0 || catalog.count !== catalog.vulnerabilities.length) throw new Error('invalid_kev_catalog');
 const seen=new Set<string>();
 const records: KevRecord[]=[];
 for(const value of catalog.vulnerabilities) {
  const row=object(value);
  if(!row || typeof row.cveID !== 'string' || !CVE.test(row.cveID.toUpperCase()) || typeof row.vendorProject !== 'string' || !row.vendorProject.trim() || typeof row.product !== 'string' || !row.product.trim() || !validDate(row.dateAdded)) throw new Error('invalid_kev_record');
  const id=row.cveID.toUpperCase();
  if(seen.has(id)) throw new Error('duplicate_kev_record');
  seen.add(id);
  records.push({...row,cveID:id} as KevRecord);
 }
 records.sort((a,b)=>a.cveID < b.cveID ? -1 : a.cveID > b.cveID ? 1 : 0);
 return {catalogVersion:catalog.catalogVersion,dateReleased:catalog.dateReleased,records};
}

/** Canonical JSON compares record content, not object key ordering. */
export function canonicalKevJson(value: unknown): string {
 const normalize=(v:unknown):unknown => {
  if(Array.isArray(v)) return v.map(normalize);
  if(v && typeof v==='object') return Object.fromEntries(Object.entries(v as Record<string,unknown>).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,normalize(x)]));
  return v;
 };
 return JSON.stringify(normalize(value));
}
