import { toASCII } from 'punycode';
import DNSException from '../exceptions/DNSException';
import Options from '../types/Options';
import {
  getOptions,
  intoSPFRecord,
  isValidDomain,
  isValidIP,
  isValidSPFRecord,
  resolveDNS,
} from '../utils/helpers';
import SPFRecord from '../types/SPFRecord';
// import ipaddr from 'ipaddr.js';

const limitedDnsCall = (
  resolverHost: string,
  maxResolve: number,
  maxVoid: number
) => {
  let resolveCount = 0;
  let voidCount = 0;

  const resolve = async (
    domain?: string,
    type?: Parameters<typeof resolveDNS>[2]
  ) => {
    resolveCount++;

    if (resolveCount > maxResolve) {
      throw new DNSException('Too many DNS requests', 'permerror');
    }

    if (!domain || !isValidDomain(domain)) {
      throw new DNSException(`Invalid domain ${domain}`, 'permerror');
    }

    try {
      const res = await resolveDNS(domain, resolverHost, type || 'TXT');

      if (!res || !res.length) {
        voidCount++;
        if (voidCount > maxVoid) {
          throw new DNSException('Too many void DNS results');
        }
        throw new DNSException('DNS call failed');
      }

      return res;
    } catch (error) {
      throw new DNSException('Unable to resolve DNS', undefined, error);
    }
  };

  return {
    resolve,
    getResolveCount: () => resolveCount,
    getVoidCount: () => voidCount,
    getResolveLimit: () => maxResolve,
  };
};

// const matchIp = (addr: ipaddr.IPv4 | ipaddr.IPv6, range: string) => {
//   if (/\/\d+$/.test(range)) {
//     // seems CIDR
//     return addr.match(ipaddr.parseCIDR(range));
//   } else {
//     return (
//       addr.toNormalizedString() === ipaddr.parse(range).toNormalizedString()
//     );
//   }
// };

const verify = async (
  domain: string,
  resolver: ReturnType<typeof limitedDnsCall>['resolve'],
  ip: string
): Promise<SPFRecord[]> => {
  if (!isValidIP(ip)) {
    throw new DNSException(`Invalid IP ${ip}`, 'permerror');
  }

  const parsedDomain = toASCII(domain);
  //   const addr = ipaddr.parse(ip);

  const response = await resolver(parsedDomain, 'TXT');

  const spfRecords = response.reduce(
    (records: SPFRecord[] | undefined, answer) => {
      const [signature, ...rest] = answer.data?.trim().split(' ') || [];

      if (signature !== 'v=spf1') {
        return records;
      }

      // if we already have records
      if (records) {
        throw new DNSException(
          `multiple SPF records found for ${domain}`,
          'permerror'
        );
      }

      if (answer.data && /[^\x20-\x7E]/.test(answer.data)) {
        throw new DNSException(
          'DNS response includes invalid characters',
          'permerror'
        );
      }

      return intoSPFRecord(rest.filter(v => !!v));
    },
    undefined
  );

  if (!spfRecords || !spfRecords.length) {
    throw new DNSException(`No SPF records for ${domain}`, 'permerror');
  }

  const [redirect, ...extraRedirects] = spfRecords.filter(
    p => p && p.token === 'redirect'
  );

  if (extraRedirects.length) {
    throw new DNSException('more than 1 redirect found', 'permerror');
  }

  // have to ignore if there is any all modifiers exists
  if (
    redirect &&
    redirect.type === 'mechanism' &&
    !spfRecords.some(r => r.token.endsWith('all'))
  ) {
    if (!isValidSPFRecord(redirect)) {
      throw new DNSException('unexpected empty value', 'permerror');
    }

    return verify(redirect.host, resolver, ip);
  }

  for (const record of spfRecords) {
    if (!isValidSPFRecord(record)) {
      throw new DNSException('unexpected empty value', 'permerror');
    }

    if (record.token === 'redirect') {
      return verify(record.host, resolver, ip);
    }

    switch (record.token) {
      case 'all':
        // @ts-expect-error: ignoring ts for strict check
        if (record.host) {
          throw new DNSException(
            'unexpected extension for all modifier',
            'permerror'
          );
        }

        // return record;
        break;

      case 'include':
        // TODO

      case 'ip4':
      case 'ip6':
        // TODO

      default:
        break;
    }
  }

  return spfRecords;
};

export const spf = async (options: Partial<Options>) => {
  const {
    dnsResolverHost,
    domain,
    ip,
    maxResolveCount,
    maxVoidCount,
  } = getOptions(options);

  //   const status = {
  //     result: 'neutral',
  //     comment: false,
  //     // ptype properties
  //     smtp: {
  //       mailfrom: sender,
  //       helo,
  //     },
  //   };

  const resolver = limitedDnsCall(
    dnsResolverHost,
    maxResolveCount,
    maxVoidCount
  );

  return {
    resolveCount: resolver.getResolveCount(),
    voidCount: resolver.getVoidCount(),
    result: await verify(domain, resolver.resolve, ip),
  };
};
