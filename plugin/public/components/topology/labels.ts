// What a node is called on the map: a real hostname when there is one, else
// the best identifier the graph holds. Pure, no React.
import { GraphNode } from "../../../common";

type Nameable = Pick<GraphNode, "node_id" | "hostname" | "ip" | "mac" | "vendor"> & {
  mac_vendor?: string | null;
};

// Names some firmware reports when it has none (a BMC announcing "(none)" over
// LLDP, a loopback name). They identify nothing, so they are never shown.
const PLACEHOLDER_WORDS = new Set(["localhost", "localhost.localdomain"]);

/**
 * True for a hostname that names nothing: empty, whitespace, "localhost", or a
 * string made only of "(none)" and dots such as "(none).(none)".
 */
export function isPlaceholderName(name: string | null | undefined): boolean {
  if (name == null) return true;
  const t = name.trim().toLowerCase();
  if (!t) return true;
  if (PLACEHOLDER_WORDS.has(t)) return true;
  return t.replace(/\(none\)/g, "").replace(/[.\s]/g, "") === "";
}

function vendorOf(node: Nameable): string | null {
  const v = (node.vendor || node.mac_vendor || "").trim();
  return v || null;
}

function realHostname(node: Nameable): string | null {
  return isPlaceholderName(node.hostname) ? null : node.hostname!.trim();
}

/** The last three octets of a MAC ("aa:bb:cc:dd:ee:ff" gives "dd:ee:ff"), or null. */
function macTail(mac: string | null | undefined): string | null {
  const parts = (mac || "").trim().toLowerCase().split(/[:\-.]/).filter(Boolean);
  return parts.length >= 6 ? parts.slice(-3).join(":") : null;
}

/** Label order: hostname, IP, vendor plus MAC tail, node_id. */
export function displayName(node: Nameable): string {
  const host = realHostname(node);
  if (host) return host;
  const ip = (node.ip || "").trim();
  if (ip) return ip;
  const tail = macTail(node.mac);
  if (tail) {
    const vendor = vendorOf(node);
    return vendor ? `${vendor} ${tail}` : tail;
  }
  return node.node_id;
}

/** The vendor, shown under the label when the label is an IP (no real hostname). */
export function displaySubtitle(node: Nameable): string | null {
  if (realHostname(node)) return null;
  return (node.ip || "").trim() ? vendorOf(node) : null;
}
