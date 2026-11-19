// Which site a node belongs to, and the per-site views of the graph. Pure.
import { GraphNode, GraphEdge, GraphResponse, NetSource } from "../../../common";

type G = Pick<GraphResponse, "nodes" | "edges">;

export const OTHER_SITE = "Other";
export const ALL_SITES = "ALL";
export const MIN_SITE_NODES = 10;
export const FIXED_SITE_TABS = ["DC1", "DC2", "D10", "SB"] as const;

export function normalizeSavedTab(tab: string | null): string | null {
  return tab === "All" ? ALL_SITES : tab;
}

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

/**
 * The tab a node lands on: its site when that site has a tab, else "Other".
 */
export function tabOf(info: Map<string, SiteInfo>, _minNodes = MIN_SITE_NODES): Map<string, string> {
  const out = new Map<string, string>();
  for (const [id, { site }] of info) {
    out.set(id, (FIXED_SITE_TABS as readonly string[]).includes(site) ? site : OTHER_SITE);
  }
  return out;
}

/**
 * Fixed site tabs in contract order, then Other for all remaining sites, then ALL.
 */
export function siteTabs(graph: G, _minNodes = MIN_SITE_NODES): string[] {
  if (!graph.nodes.length) return [];
  const tabs = tabOf(siteOf(graph));
  const present = new Set(tabs.values());
  const sites = FIXED_SITE_TABS.filter((s) => present.has(s));
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
 * The "ALL" tab returns the whole graph unchanged and no badges.
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
