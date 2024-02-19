export const DNS_RECORD_TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  NAPTR: 35,
  CERT: 37,
  DNSKEY: 48,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  TLSA: 52,
  CAA: 257,
} as const;

export const SPF_QUALIFIERS = ['?', '-', '+', '~'] as const;

export const SPF_MODIFIERS = ['all', 'exp'] as const;

export const SPF_MECHANISM = [
  'a',
  'a:PTR',
  'a:SPF',
  'mx',
  'ip4',
  'ip6',
  'all',
  'ptr',
  'exists',
  'ext',
  'st',
  'redirect',
  'include',
] as const;
