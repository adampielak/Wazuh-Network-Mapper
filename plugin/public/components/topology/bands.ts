// Banded layout: when nodes carry a network role (net_role), the map is drawn
// in fixed rows by role instead of by hop distance from one root. Pure.
//
//   band -1  ISP  (only when shown)
//   band  0  BR   border routers, always the top row
//   band  1  SP   spine
//   band  2  LF   leaf
//   band  3  FW, SW, MGT, SW-CCTV  access, sub-ranked by hops from the bands above
//   band  4  SRV, AI-SRV
//   below    nodes without a role: one band under their best-banded neighbour,
//            and a lane under everything when no banded neighbour exists.
// Left to right inside a band is the barycentre order of wrapRanks, and a
// single-neighbour leaf is drawn as a grid under its parent, as in layout.ts.
import { GraphNode, GraphResponse, NetRole } from "../../../common";
import {
  LayoutNode,
  LayoutResult,
  NODE_H,
  NODE_W,
  PEND_COLS_MAX,
  PEND_TOP_GAP,
  LANE_GAP,
  WrapItem,
  blockOf,
  buildAdjacency,
  confirmedEdges,
  gridPositions,
  wrapRanks,
} from "./layout";

type G = Pick<GraphResponse, "nodes" | "edges">;

export type BandOptions = {
  /** draw the ISP row above the border routers; off removes ISP nodes and their links */
  showIsp?: boolean;
  /** swimlanes: node_id to lane name, one side-by-side lane per name */
  laneOf?: Map<string, string>;
  /** lane order; lanes missing here follow in order of appearance */
  laneOrder?: string[];
};

const BANDS: Record<NetRole, number> = {
  ISP: -1,
  BR: 0,
  SP: 1,
  LF: 2,
  FW: 3,
  SW: 3,
  MGT: 3,
  "SW-CCTV": 3,
  SRV: 4,
  "AI-SRV": 4,
};
const ACCESS = 3;
// Ranks are spaced far apart in y so that wrapRanks keeps them as separate rows.
const RANK_STEP = 1000;
const LANE_X_GAP = 240;

/**
 * How many nodes one line of a band holds before it folds. Smaller than the
 * legacy capacity for small maps, so a 12-node site is not one flat strip.
 */
export function bandRowCapacity(count: number): number {
  return Math.max(5, Math.ceil(Math.sqrt(count * 1.2)));
}

/** The band of a role, or null for no role or a role this layout does not know. */
export function bandOf(role: string | null | undefined): number | null {
  return role != null && Object.prototype.hasOwnProperty.call(BANDS, role) ? BANDS[role as NetRole] : null;
}

/** True when at least one node carries a role this layout knows. */
export function hasBands(graph: G | null | undefined): boolean {
  return !!graph && graph.nodes.some((n) => bandOf(n.net_role) != null);
}

/** The graph without ISP nodes and the links that touch them. */
export function withoutIsp<T extends G>(graph: T): T {
  const isp = new Set(graph.nodes.filter((n) => n.net_role === "ISP").map((n) => n.node_id));
  if (!isp.size) return graph;
  return {
    ...graph,
    nodes: graph.nodes.filter((n) => !isp.has(n.node_id)),
    edges: graph.edges.filter((e) => !isp.has(e.source) && !isp.has(e.target)),
  };
}

type Lane = { place: Map<string, { x: number; y: number }>; tier: Map<string, number> };

function layoutLane(nodes: GraphNode[], edges: G["edges"]): Lane {
  const adj = buildAdjacency(nodes, edges);
  const band = new Map<string, number>();
  for (const n of nodes) {
    const b = bandOf(n.net_role);
    if (b != null) band.set(n.node_id, b);
  }

  // A node without a role goes one band below its best-banded neighbour. Run to
  // a fixpoint so a chain of role-less nodes hangs under the banded node above.
  const own = new Set(band.keys());
  for (let changed = true; changed; ) {
    changed = false;
    for (const n of nodes) {
      if (own.has(n.node_id)) continue;
      let best: number | null = null;
      for (const nb of adj.get(n.node_id) || []) {
        const b = band.get(nb);
        if (b != null && (best == null || b < best)) best = b;
      }
      if (best != null && band.get(n.node_id) !== best + 1) {
        band.set(n.node_id, best + 1);
        changed = true;
      }
    }
  }
  const lane = nodes.filter((n) => !band.has(n.node_id)).map((n) => n.node_id);
  const banded = nodes.filter((n) => band.has(n.node_id));

  // Pendants: a node without a role whose only neighbour sits in a higher band
  // hangs under it. A node with a role always keeps its own band.
  const parentOf = new Map<string, string>();
  for (const n of banded) {
    if (own.has(n.node_id)) continue;
    const nbs = adj.get(n.node_id)!;
    if (nbs.size !== 1) continue;
    const p = [...nbs][0];
    if (!band.has(p) || (adj.get(p)?.size || 0) < 2) continue;
    if (band.get(n.node_id)! > band.get(p)!) parentOf.set(n.node_id, p);
  }
  for (const p of new Set(parentOf.values())) parentOf.delete(p);
  const groups = new Map<string, string[]>();
  for (const [c, p] of parentOf) groups.set(p, [...(groups.get(p) || []), c]);
  const backbone = banded.filter((n) => !parentOf.has(n.node_id));

  // The access band is split by hops from the bands above it. A link between
  // two MGT nodes is lateral and does not add a hop.
  const hop = new Map<string, number>();
  const access = backbone.filter((n) => band.get(n.node_id) === ACCESS && bandOf(n.net_role) != null);
  const accessIds = new Set(access.map((n) => n.node_id));
  const queue: string[] = [];
  for (const n of access) {
    if ([...adj.get(n.node_id)!].some((nb) => (band.get(nb) ?? ACCESS) < ACCESS)) {
      hop.set(n.node_id, 0);
      queue.push(n.node_id);
    }
  }
  const role = new Map(nodes.map((n) => [n.node_id, n.net_role]));
  for (let head = 0; head < queue.length; head++) {
    const cur = queue[head];
    for (const nb of adj.get(cur)!) {
      if (!accessIds.has(nb) || hop.has(nb)) continue;
      if (role.get(cur) === "MGT" && role.get(nb) === "MGT") continue;
      hop.set(nb, hop.get(cur)! + 1);
      queue.push(nb);
    }
  }
  const keyOf = (id: string) => band.get(id)! * 100 + (hop.get(id) ?? 0);
  const keys = [...new Set(backbone.map((n) => keyOf(n.node_id)))].sort((a, b) => a - b);
  const rank = new Map(keys.map((k, i) => [k, i]));
  const tier = new Map<string, number>();
  for (const n of backbone) tier.set(n.node_id, rank.get(keyOf(n.node_id))!);

  const blocks = new Map(
    [...groups].map(([p, kids]) => [p, blockOf(kids.length, PEND_COLS_MAX)] as const)
  );
  const boxW = (id: string) => Math.max(NODE_W, blocks.get(id)?.w || 0);
  const boxH = (id: string) => NODE_H + (blocks.has(id) ? PEND_TOP_GAP + blocks.get(id)!.h : 0);

  const items: WrapItem[] = backbone.map((n, i) => ({
    id: n.node_id,
    position: { x: i, y: tier.get(n.node_id)! * RANK_STEP },
    w: boxW(n.node_id),
    h: boxH(n.node_id),
  }));
  const parentsOf = new Map<string, string[]>();
  for (const e of edges) {
    const a = tier.get(e.source);
    const b = tier.get(e.target);
    if (a == null || b == null || a === b) continue;
    const [from, to] = a < b ? [e.source, e.target] : [e.target, e.source];
    parentsOf.set(to, [...(parentsOf.get(to) || []), from]);
  }
  wrapRanks(items, bandRowCapacity(nodes.length), parentsOf);

  const place = new Map<string, { x: number; y: number }>();
  let lowest = 0;
  for (const box of items) {
    place.set(box.id, { x: box.position.x + (box.w - NODE_W) / 2, y: box.position.y });
    lowest = Math.max(lowest, box.position.y + box.h);
    const kids = groups.get(box.id);
    if (!kids) continue;
    const cells = gridPositions(
      kids.length,
      blocks.get(box.id)!,
      box.position.x + box.w / 2,
      box.position.y + NODE_H + PEND_TOP_GAP
    );
    kids.forEach((c, i) => {
      place.set(c, cells[i]);
      tier.set(c, tier.get(box.id)! + 1);
    });
  }
  if (lane.length) {
    const cells = gridPositions(
      lane.length,
      blockOf(lane.length, bandRowCapacity(nodes.length)),
      0,
      lowest + (backbone.length ? LANE_GAP : 0)
    );
    const laneTier = keys.length + 1;
    lane.forEach((id, i) => {
      place.set(id, cells[i]);
      tier.set(id, laneTier);
    });
  }
  return { place, tier };
}

/**
 * Banded layout of the graph. With `laneOf`, each lane is laid out on its own
 * and the lanes stand side by side, left to right.
 */
export function layoutBands(graph: G, opts: BandOptions = {}): LayoutResult {
  const g = opts.showIsp ? graph : withoutIsp(graph);
  const nodes = g.nodes;
  if (!nodes.length) return { nodes: [], edges: [] };

  const names: string[] = [];
  const members = new Map<string, GraphNode[]>();
  for (const n of nodes) {
    const name = opts.laneOf?.get(n.node_id) ?? "";
    if (!members.has(name)) {
      members.set(name, []);
      names.push(name);
    }
    members.get(name)!.push(n);
  }
  const order = [
    ...(opts.laneOrder || []).filter((l) => members.has(l)),
    ...names.filter((l) => !(opts.laneOrder || []).includes(l)),
  ];

  const place = new Map<string, { x: number; y: number }>();
  const tier = new Map<string, number>();
  let cursor = 0;
  for (const name of order) {
    const ns = members.get(name)!;
    const ids = new Set(ns.map((n) => n.node_id));
    const lane = layoutLane(
      ns,
      g.edges.filter((e) => ids.has(e.source) && ids.has(e.target))
    );
    const xs = [...lane.place.values()].map((p) => p.x);
    const shift = cursor - Math.min(...xs);
    for (const [id, p] of lane.place) place.set(id, { x: p.x + shift, y: p.y });
    for (const [id, t] of lane.tier) tier.set(id, t);
    cursor += Math.max(...xs) + NODE_W - Math.min(...xs) + LANE_X_GAP;
  }

  const outNodes: LayoutNode[] = nodes.map((n) => ({
    id: n.node_id,
    type: "device",
    position: place.get(n.node_id) || { x: 0, y: 0 },
    tier: tier.get(n.node_id) ?? 0,
    data: n,
  }));
  return { nodes: outNodes, edges: confirmedEdges(nodes, g.edges) };
}
