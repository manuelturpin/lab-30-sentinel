/**
 * URL validation to prevent SSRF against private, loopback, link-local,
 * and cloud metadata endpoints.
 *
 * Reject: RFC 1918, 127/8, 169.254/16 (incl. AWS/GCE metadata), 0/8,
 *         IPv6 loopback (::1), ULA (fc00::/7), link-local (fe80::/10),
 *         known metadata hostnames, non-http(s) schemes.
 */
import { URL } from "node:url";

type V4Range = [number, number, number, number, number];

const PRIVATE_V4_RANGES: V4Range[] = [
  [10, 0, 0, 0, 8],
  [172, 16, 0, 0, 12],
  [192, 168, 0, 0, 16],
  [127, 0, 0, 0, 8],
  [169, 254, 0, 0, 16],
  [0, 0, 0, 0, 8],
];

const PRIVATE_HOSTNAMES = new Set<string>([
  "localhost",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
]);

function ipv4ToOctets(host: string): [number, number, number, number] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return octets as [number, number, number, number];
}

function inCidr(
  octets: [number, number, number, number],
  range: V4Range
): boolean {
  const [a, b, c, d, prefix] = range;
  const ipInt =
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>>
    0;
  const rangeInt = (((a << 24) | (b << 16) | (c << 8) | d) >>> 0);
  const mask = prefix === 0 ? 0 : (~((1 << (32 - prefix)) - 1)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

export function isPublicUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return false;

  // Strip IPv6 brackets
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return false;

  if (PRIVATE_HOSTNAMES.has(host)) return false;

  // IPv6 loopback / ULA / link-local
  if (host === "::1") return false;
  if (host.startsWith("fc") || host.startsWith("fd")) return false; // fc00::/7
  if (host.startsWith("fe80:")) return false; // fe80::/10

  const octets = ipv4ToOctets(host);
  if (octets) {
    return !PRIVATE_V4_RANGES.some((range) => inCidr(octets, range));
  }
  return true;
}
