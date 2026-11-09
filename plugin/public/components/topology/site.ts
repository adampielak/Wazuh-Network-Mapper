// Which site a node belongs to, and the per-site views of the graph. Pure.
import { GraphNode, GraphEdge, GraphResponse, NetSource } from "../../../common";

type G = Pick<GraphResponse, "nodes" | "edges">;

export const OTHER_SITE = "Other";
export const ALL_SITES = "All";
export const MIN_SITE_NODES = 10;

export type SiteInfo = { site: string; source: NetSource | null };

const SEED_SOURCES = new Set<string>(["netbox", "zabbix", "name"]);

function cleanSite(n: Pick<GraphNode, "site">): string | null {
  const s = typeof n.site === "string" ? n.site.trim() : "";
  return s || null;
}

// A seed carries a site from a real source. A site without a recorded source
// still counts as given by the data; only inherited values are never seeds.
function isSeed(n: GraphNode): boolean {
  return cleanSite(n) != null && n.site_source !== "neighbour";
}

function neighbours(graph: G): Map<string, Set<string>> {
  const adj = new Map<string, Set<string>>();
  for (const n of graph.nodes) adj.set(n.node_id, new Set());
  for (const e of graph.edges || []) {
    adj.get(e.source)?.add(e.target);
    adj.get(e.target)?.add(e.source);
  }
  return adj;
}

/**
 * The site of every node. A node with a site keeps it. A node without one takes
 * its neighbours' site when it has at least one classified neighbour and they
 * all agree (source "neighbour"), in one pass: inherited values never seed
 * another node. Anything else is "Other" with no source.
 */
export function siteOf(graph: G): Map<string, SiteInfo> {
  const byId = new Map(graph.nodes.map((n) => [n.node_id, n]));
  const adj = neighbours(graph);
  const out = new Map<string, SiteInfo>();
  for (const n of graph.nodes) {
    const own = cleanSite(n);
    if (own) {
      const src = n.site_source && SEED_SOURCES.has(n.site_source) ? n.site_source : null;
      out.set(n.node_id, { site: own, source: n.site_source === "neighbour" ? "neighbour" : src });
      continue;
    }
    const seen = new Set<string>();
    for (const id of adj.get(n.node_id) || []) {
      const nb = byId.get(id);
      if (nb && isSeed(nb)) seen.add(cleanSite(nb)!);
    }
    out.set(
      n.node_id,
      seen.size === 1 ? { site: [...seen][0], source: "neighbour" } : { site: OTHER_SITE, source: null }
    );
  }
  return out;
}

// DC sites first in numeric order, then the rest alphabetically.
function compareSites(a: string, b: string): number {
  const da = /^DC(\d+)$/.exec(a);
  const db = /^DC(\d+)$/.exec(b);
  if (da && db) return Number(da[1]) - Number(db[1]);
  if (da) return -1;
  if (db) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * The tab a node lands on: its site when that site has a tab, else "Other".
 */
export function tabOf(info: Map<string, SiteInfo>, minNodes = MIN_SITE_NODES): Map<string, string> {
  const counts = new Map<string, number>();
  for (const { site } of info.values()) counts.set(site, (counts.get(site) || 0) + 1);
  const out = new Map<string, string>();
  for (const [id, { site }] of info) {
    out.set(id, site !== OTHER_SITE && (counts.get(site) || 0) >= minNodes ? site : OTHER_SITE);
  }
  return out;
}

/**
 * Tab names: every site holding at least `minNodes` nodes, then "Other" when
 * anything falls outside them, then "All". Empty when no node has a site, so a
 * graph without classification shows no tabs.
 */
export function siteTabs(graph: G, minNodes = MIN_SITE_NODES): string[] {
  if (!graph.nodes.some((n) => cleanSite(n))) return [];
  const tabs = tabOf(siteOf(graph), minNodes);
  const sites = [...new Set(tabs.values())].filter((s) => s !== OTHER_SITE).sort(compareSites);
  const hasOther = [...tabs.values()].includes(OTHER_SITE);
  return [...sites, ...(hasOther ? [OTHER_SITE] : []), ALL_SITES];
}

export type CrossLink = { tab: string; peers: string[] };

export type SiteView<T extends G = G> = {
  graph: T;
  /** per node: links leaving this tab, grouped by the tab on the far side */
  cross: Map<string, CrossLink[]>;
  /** edges between two different tabs over the whole graph */
  crossEdges: number;
};

/**
 * The graph of one tab: its nodes and the edges between them. Every node with
 * a link into another tab is listed in `cross`, with the peers it links to.
 * The "All" tab returns the whole graph unchanged and no badges.
 */
export function filterBySite<T extends G>(graph: T, tab: string, minNodes = MIN_SITE_NODES): SiteView<T> {
  const tabs = tabOf(siteOf(graph), minNodes);
  const nameOf = new Map(graph.nodes.map((n) => [n.node_id, n.hostname || n.node_id]));
  let crossEdges = 0;
  const cross = new Map<string, Map<string, string[]>>();
  const note = (id: string, peer: string) => {
    const t = tabs.get(peer)!;
    const m = cross.get(id) || new Map<string, string[]>();
    m.set(t, [...(m.get(t) || []), nameOf.get(peer)!]);
    cross.set(id, m);
  };
  const edges: GraphEdge[] = [];
  for (const e of graph.edges || []) {
    const a = tabs.get(e.source);
    const b = tabs.get(e.target);
    if (a == null || b == null) continue;
    if (a !== b) {
      crossEdges++;
      if (a === tab) note(e.source, e.target);
      if (b === tab) note(e.target, e.source);
    } else if (tab === ALL_SITES || a === tab) {
      edges.push(e);
    }
  }
  if (tab === ALL_SITES) {
    return { graph, cross: new Map(), crossEdges };
  }
  return {
    graph: { ...graph, nodes: graph.nodes.filter((n) => tabs.get(n.node_id) === tab), edges },
    cross: new Map(
      [...cross].map(([id, m]) => [id, [...m].map(([t, peers]) => ({ tab: t, peers }))])
    ),
    crossEdges,
  };
}
