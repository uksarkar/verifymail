import { defaults } from 'lodash-es';
import { produce } from 'immer';
import Options from '../types/Options';
import ParsedOptions from '../types/ParsedOptions';
import { z } from 'zod';
import { DNS_RECORD_TYPES, SPF_MODIFIERS, SPF_QUALIFIERS } from './constants';
import DNSAnswer from '../types/DNSAnswer';
import SPFRecord from '../types/SPFRecord';

/**
 * Get option parsed with default values
 *
 * @param options provided options
 * @returns parsed with default values
 */
export const getOptions = (options: Partial<Options>): ParsedOptions => {
  console.log('FOUNDED');
  console.log(options);
  return (produce(
    defaults(
      {
        maxResolveCount: 10,
        maxVoidCount: 2,
      },
      options
    ),
    (draft: ParsedOptions) => {
      if (!options.sender) {
        draft.sender = `postmaster@${options.helo}`;
      }

      const ipv4 = options.ip?.toString().match(/^[:A-F]+:((\d+\.){3}\d+)$/i);

      if (ipv4) {
        draft.ip = ipv4[1];
      }

      let atPos = options.sender?.indexOf('@');

      if (atPos !== undefined && atPos < 0) {
        draft.sender = `postmaster@${options.sender}`;
      } else if (atPos !== undefined && atPos === 0) {
        draft.sender = `postmaster${options.sender}`;
      }

      draft.domain =
        draft.sender
          .split('@')
          .pop()
          ?.toLowerCase()
          .trim() || '-';

      if (!options.dnsResolverHost) {
        draft.dnsResolverHost = `https://dns.google/resolve`;
      }
    }
  ) as unknown) as ParsedOptions;
};

/**
 * Resolves DNS records for a given domain using a specified resolver.
 * @param domain The domain name to resolve DNS records for.
 * @param resolverHost The DNS resolver host URL or a template string that includes '{domain}' and '{type}' placeholders.
 * @param type The type of DNS record to resolve (e.g., 'A', 'AAAA', 'MX', 'TXT').
 * @returns A Promise resolving to the DNS response data if successful, or false otherwise.
 */
export const resolveDNS = async (
  domain: string,
  resolverHost: string,
  type: 'TXT' | 'A' | 'AAAA' | 'MX'
): Promise<DNSAnswer[] | false> => {
  // Construct the URL for DNS resolution
  const url = (() => {
    // If resolverHost includes placeholders for {domain} and {type}, replace them with actual values
    if (resolverHost.includes('{domain}')) {
      return resolverHost.replace('{domain}', domain).replace('{type}', type);
    }

    // Otherwise, treat resolverHost as a complete URL and append query parameters for domain and type
    const host = new URL(resolverHost);
    host.searchParams.set('name', domain);
    host.searchParams.set('type', type);

    return host;
  })();

  // Fetch DNS records from the resolved URL
  const response = await fetch(url);

  // If the response is not successful, return false
  if (!response.ok) {
    return false;
  }

  // Otherwise, parse and return the JSON response
  return (
    ((await response.json()) as {
      Answer: DNSAnswer[];
    })?.Answer?.map(ans => ({ ...ans, type: parseDnsType(ans.type) })) || false
  );
};

/**
 * Checks if a given string conforms to the format of a valid domain name.
 * @param domain The domain name to validate.
 * @returns True if the domain is valid, false otherwise.
 */
export const isValidDomain = (domain?: string): boolean => {
  // Define a Zod schema for validating domain names
  const validator = z
    .string()
    .min(3) // Ensure the domain name has at least 3 characters
    .refine(value => {
      // Regular expression to match a valid domain name format
      const domainRegex = /^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,}$/;
      return domainRegex.test(value);
    });

  // Parse the domain using the validator and return true if parsing is successful
  return validator.safeParse(domain).success;
};

/**
 * Checks if a given string conforms to the format of a valid IPv4 or IPv6 address.
 * @param ip The IP address to validate.
 * @returns True if the IP address is valid, false otherwise.
 */
export const isValidIP = (ip?: string): boolean => {
  // Define a Zod schema for validating IP addresses
  const validator = z.string().refine(value => {
    // Regular expressions to match valid IPv4 and IPv6 address formats
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
    return ipv4Regex.test(value) || ipv6Regex.test(value);
  });

  // Parse the IP address using the validator and return true if parsing is successful
  return validator.safeParse(ip).success;
};

/**
 * Make the text representation of the type if it's in a numeric form
 *
 * @param type
 * @returns
 */
export const parseDnsType = (type: number | string): DNSAnswer['type'] => {
  if (typeof type === 'string') {
    return type as DNSAnswer['type'];
  }

  return Object.keys(DNS_RECORD_TYPES).find(
    key => DNS_RECORD_TYPES[key as keyof unknown] === type
  ) as DNSAnswer['type'];
};

/**
 * Convert a SPF records into defined type
 *
 * @param records
 * @returns
 */
export const intoSPFRecord = (records: string[]): SPFRecord[] => {
  return records.map(record => {
    const [token, host] = record.split(':');
    const isModifier = SPF_MODIFIERS.includes(token as keyof unknown);
    const [t, qualifier] = (() => {
      const q = SPF_QUALIFIERS.find(qf => token.startsWith(qf));
      if (!q) {
        return [token];
      }

      return [token.replace(q, ''), q];
    })();

    return {
      token: t,
      host,
      type: isModifier ? 'modifier' : 'mechanism',
      qualifier,
    } as SPFRecord;
  });
};

/**
 * Validate a record based on the record type
 *
 * @param record
 * @returns
 */
export const isValidSPFRecord = (record: SPFRecord): boolean => {
  return record.type !== 'mechanism' || !!record.host;
};
