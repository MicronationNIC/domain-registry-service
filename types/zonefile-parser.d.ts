declare module 'zonefile-parser' {
  export interface ZoneRecord {
    name?: string;
    ttl?: number | string;
    class?: string;
    type: string;
    // SOA fields
    mname?: string;
    rname?: string;
    serial?: number | string;
    refresh?: number | string;
    retry?: number | string;
    expire?: number | string;
    minimum?: number | string;
    // Common RR data fields (A, AAAA, CNAME, NS, PTR, MX, TXT, SRV, CAA, etc.)
    ip?: string;
    host?: string;
    alias?: string;
    preference?: number | string;
    priority?: number | string;
    weight?: number | string;
    port?: number | string;
    target?: string;
    txt?: string | string[];
    flags?: number | string;
    tag?: string;
    value?: string;
    [key: string]: unknown;
  }

  export interface ParsedZoneFile {
    $origin?: string;
    $ttl?: number | string;
    records: ZoneRecord[];
  }

  export function parse(zoneFileContent: string): ParsedZoneFile;

  const zonefileParser: {
    parse: typeof parse;
  };

  export default zonefileParser;
}
