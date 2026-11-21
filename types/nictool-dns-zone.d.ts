declare module '@nictool/dns-zone' {
  export type ZoneFormat = 'rfc1035' | 'bind' | 'tinydns' | 'maradns' | 'json';

  export interface ZoneResourceRecord {
    owner: string;
    ttl?: number;
    class: string;
    type: string;
    [key: string]: unknown;
    toBind?(): string;
    toTinydns?(): string;
    toMaraDNS?(): string;
    toJSON?(): Record<string, unknown>;
  }

  export interface ParseOptions {
    /** Zone $ORIGIN (e.g., 'example.com.') */
    origin?: string;
    /** Default TTL in seconds */
    ttl?: number;
    /** Zone class (default: 'IN') */
    class?: string;
    /** File path used to resolve $INCLUDE directives */
    file?: string;
  }

  export interface ValidateZoneOptions extends ParseOptions {
    /** Input parser format (default: 'rfc1035') */
    format?: ZoneFormat;
  }

  export interface ZoneValidationError {
    zone: string;
    rr?: ZoneResourceRecord;
    error: string | Error;
  }

  export interface ValidateZoneResult {
    RR: ZoneResourceRecord[];
    errors: ZoneValidationError[];
  }

  export interface SplitByZoneOptions {
    manyZones?: boolean;
  }

  export interface ZoneConstructorOptions {
    origin: string;
    RR: ZoneResourceRecord[];
  }

  export class ZONE {
    origin: string;
    RR: ZoneResourceRecord[];
    errors: ZoneValidationError[];
    constructor(options: ZoneConstructorOptions);
  }

  export const bind: {
    parseZoneFile(zoneText: string, options?: ParseOptions): Promise<ZoneResourceRecord[]>;
  };

  export const rfc1035: typeof bind;

  export const json: {
    parseZoneFile(ndjsonText: string, options?: ParseOptions): Promise<ZoneResourceRecord[]>;
  };

  export const maradns: {
    parseZoneFile(csv2Text: string, options?: ParseOptions): Promise<ZoneResourceRecord[]>;
  };

  export const tinydns: {
    parseData(dataText: string, options?: ParseOptions): Promise<ZoneResourceRecord[]>;
  };

  export function validateZone(
    zoneData: string,
    options?: ValidateZoneOptions
  ): Promise<ValidateZoneResult>;

  export function splitByZone(
    RR: ZoneResourceRecord[],
    options?: SplitByZoneOptions
  ): Record<string, ZoneResourceRecord[]>;
}
