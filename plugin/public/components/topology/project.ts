// Project tabs: a cross-cutting subset of the graph (the nodes tagged with one
// project), shown next to the site tabs. Unlike a site, a project does not
// partition the graph: a member keeps its place on its site tab too. Pure.
import { GraphEdge, GraphNode, GraphResponse } from "../../../common";
import { MIN_SITE_NODES, SiteView, siteOf, tabOf } from "./site";

type G = Pick<GraphResponse, "nodes" | "edges">;

// Prefix of a project tab key, so a project can never collide with a site name.
export const PROJECT_TAB_PREFIX = "project:";

export function isProjectTab(tab: string | null | undefined): boolean {
  return !!tab && tab.startsWith(PROJECT_TAB_PREFIX);
}

export function projectTabKey(project: string): string {
  return PROJECT_TAB_PREFIX + project;
}

export function projectOfTab(tab: string): string {
  return tab.slice(PROJECT_TAB_PREFIX.length);
}

// The cleaned project names of one node: trimmed, non-empty, unique.
export function projectsOf(n: Pick<GraphNode, "projects">): string[] {
  if (!Array.isArray(n.projects)) return [];
  const out = new Set<string>();
  for (const p of n.projects) {
    const s = typeof p === "string" ? p.trim() : "";
    if (s) out.add(s);
  }
  return [...out];
}

/**
 * Project tab keys, one per project that tags at least one node. Empty when no
 * node carries a project; fixed project names retain their contract order.
 */
export function projectTabs(graph: G): string[] {
  const names = new Set<string>();
  for (const n of graph.nodes) for (const p of projectsOf(n)) names.add(p);
  const order = ["DCMS", "AI", "VMWare"];
  return [...names].sort((a, b) => {
    const ai = order.indexOf(a), bi = order.indexOf(b);
    if (ai >= 0 || bi >= 0) return (ai < 0 ? order.length : ai) - (bi < 0 ? order.length : bi);
    return a < b ? -1 : a > b ? 1 : 0;
  }).map(projectTabKey);
}

export function topologyTabs(sites: string[], projects: string[]): string[] {
  const available = new Set([...sites, ...projects]);
  const fixed = ["DC1", "DC2", projectTabKey("DCMS"), projectTabKey("AI"), "D10", "SB",
    projectTabKey("VMWare")];
  const ordered = fixed.filter((name) => available.has(name));
  const otherProjects = projects.filter((name) => !fixed.includes(name));
  return [...ordered, ...otherProjects,
    ...(available.has("Other") ? ["Other"] : []),
    ...(available.has("ALL") ? ["ALL"] : [])];
}

/**
 * The graph of one project tab: its member nodes and the edges between them.
 * A member with a link to a node outside the project is listed in `cross`,
 * with the peers grouped by the site tab they sit on. `crossEdges` counts the
 * edges between a member and a non-member.
 */
export function filterByProject<T extends G>(graph: T, tab: string, minNodes = MIN_SITE_NODES): SiteView<T> {
  const project = projectOfTab(tab);
  const member = new Set(graph.nodes.filter((n) => projectsOf(n).includes(project)).map((n) => n.node_id));
  const known = new Set(graph.nodes.map((n) => n.node_id));
  const sites = tabOf(siteOf(graph), minNodes);
  const nameOf = new Map(graph.nodes.map((n) => [n.node_id, n.hostname || n.node_id]));
  const cross = new Map<string, Map<string, string[]>>();
  const note = (id: string, peer: string) => {
    const t = sites.get(peer)!;
    const m = cross.get(id) || new Map<string, string[]>();
    m.set(t, [...(m.get(t) || []), nameOf.get(peer)!]);
    cross.set(id, m);
  };
  let crossEdges = 0;
  const edges: GraphEdge[] = [];
  for (const e of graph.edges || []) {
    if (!known.has(e.source) || !known.has(e.target)) continue;
    const a = member.has(e.source);
    const b = member.has(e.target);
    if (a && b) edges.push(e);
    else if (a) {
      crossEdges++;
      note(e.source, e.target);
    } else if (b) {
      crossEdges++;
      note(e.target, e.source);
    }
  }
  return {
    graph: { ...graph, nodes: graph.nodes.filter((n) => member.has(n.node_id)), edges },
    cross: new Map([...cross].map(([id, m]) => [id, [...m].map(([t, peers]) => ({ tab: t, peers }))])),
    crossEdges,
  };
}
