import { layoutGraph } from './layout';
import { legacyGraph } from './layout.legacy.fixture';
import snapshot from './__snapshots__/legacy-layout.json';

(globalThis as any).structuredClone ??= (v: unknown) => JSON.parse(JSON.stringify(v));

// The snapshot was written by the layout before role bands existed. A graph
// without net_role must keep producing exactly that output.
describe('layoutGraph on a graph without net_role', () => {
  const r = layoutGraph(legacyGraph() as any);
  const slim = { nodes: r.nodes.map((n) => ({ id: n.id, position: n.position, tier: n.tier })), edges: r.edges };

  it('matches the layout recorded before role bands', () => {
    expect(JSON.parse(JSON.stringify(slim))).toEqual(snapshot);
  });

  it('ignores band options', () => {
    const o = layoutGraph(legacyGraph() as any, { showIsp: true });
    expect(JSON.parse(JSON.stringify({ nodes: o.nodes.map((n) => ({ id: n.id, position: n.position, tier: n.tier })), edges: o.edges }))).toEqual(snapshot);
  });
});
