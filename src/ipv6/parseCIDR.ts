import { ip2long, long2ip, isValidIP } from './index';

interface SubNet {
  ipCount: bigint;
  lastHost: string,
  firstHost: string,
  prefixLength: number;
}

/**
 * Parse CIDR format address into address range info
 *
 * NetworkAddress and broadcastAddress are valid when mask < 31
 *
 * @param cidr - The CIDR format address string
 * @returns The parsed address range object or false if invalid
 * 
 * @example
 * ```
 * parseCIDR('::9999:ffff/118')
 * // {
 * //   ipCount: 1024n,  
 * //   cidrMask: 118, 
 * //   firstHost: '::9999:fc00', 
 * //   lastHost: '::9999:ffff',
 * // }
 * ``` 
 */

export function parseCIDR(cidr: string) {
  if (typeof cidr !== 'string') return false;
  
  // fixing cases where user put another invalid stuffs after /
  const cidrTokens = cidr.split('/');
  if (cidrTokens.length !== 2) return false;
  const [ip, mask] = cidrTokens;
  if (ip === undefined || mask === undefined ||
    !mask.match(/^[0-9]+$/)) return false;

  const prefixLength = +mask;
  if (!isValidIP(ip) || isNaN(prefixLength) || prefixLength < 0 || prefixLength > 128) return false;

  // 计算网络地址和主机地址位数
  const length = BigInt(128 - prefixLength);
  const longIP = ip2long(ip) as bigint;
  const ipCount = BigInt(0b1n << length);
  const networkIP = (longIP >> length) << length;
  const firstHost = long2ip(networkIP) as string;
  const lastHost = long2ip(networkIP | ipCount - 1n) as string;

  const cidrInfo: SubNet = {
    ipCount,
    firstHost,
    lastHost,
    prefixLength,
  };

  return cidrInfo;
}