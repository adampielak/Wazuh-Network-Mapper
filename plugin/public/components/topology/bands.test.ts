import { bandOf, hasBands, layoutBands, withoutIsp } from './bands';
import { layoutGraph } from './layout';
import { bandedGraph } from './bands.fixture';

(globalThis as any).structuredClone ??= (v: unknown) => JSON.parse(JSON.stringify(v));

const g = bandedGraph() as any;
const role = new Map<string, string | undefined>(g.nodes.map((n: any) => [n.node_id, n.net_role]));
const ys = (r: ReturnType<typeof layoutBands>, pick: (id: string) => boolean) =>
  r.nodes.filter((n) => pick(n.id)).map((n) => n.position.y);

describe('bandOf', () => {
  it('maps the canonical roles and nothing else', () => {
    expect(bandOf('BR')).toBe(0);
    expect(bandOf('ISP')).toBe(-1);
    expect(bandOf('SW-CCTV')).toBe(3);
    expect(bandOf('AI-SRV')).toBe(4);
    expect(bandOf('MONITORING')).toBeNull();
    expect(bandOf('toString')).toBeNull();
    expect(bandOf(null)).toBeNull();
    expect(bandOf(undefined)).toBeNull();
  });
  it('hasBands only when a known role is present', () => {
    expect(hasBands(g)).toBe(true);
    expect(hasBands({ nodes: [{ node_id: 'a', net_role: 'XX' }], edges: [] } as any)).toBe(false);
  });
});

describe('layoutBands', () => {
  const r = layoutBands(g, { showIsp: false });

  it('drops ISP nodes and their links unless shown', () => {
    expect(r.nodes.some((n) => role.get(n.id) === 'ISP')).toBe(false);
    expect(r.edges.every((e) => role.get(e.source) !== 'ISP' && role.get(e.target) !== 'ISP')).toBe(true);
    expect(withoutIsp(g).nodes.length).toBe(g.nodes.length - 2);
  });

  it('puts every BR on the shared top row', () => {
    const br = ys(r, (id) => role.get(id) === 'BR');
    expect(br.length).toBe(4);
    expect(new Set(br).size).toBe(1);
    expect(Math.min(...br)).toBe(Math.min(...r.nodes.map((n) => n.position.y)));
  });

  it('keeps bands strictly ordered top to bottom', () => {
    const order = ['BR', 'SP', 'LF', 'SW', 'SRV'];
    for (let i = 0; i + 1 < order.length; i++) {
      const upper = ys(r, (id) => role.get(id) === order[i]);
      const lower = ys(r, (id) => role.get(id) === order[i + 1]);
      expect(Math.min(...lower)).toBeGreaterThan(Math.max(...upper));
    }
  });

  it('places the ISP row above BR when shown', () => {
    const s = layoutBands(g, { showIsp: true });
    const isp = ys(s, (id) => role.get(id) === 'ISP');
    const br = ys(s, (id) => role.get(id) === 'BR');
    expect(isp.length).toBe(2);
    expect(Math.max(...isp)).toBeLessThan(Math.min(...br));
  });

  it('hangs a role-less node under its best-banded neighbour', () => {
    const at = (id: string) => r.nodes.find((n) => n.id === id)!.position.y;
    expect(at('S1:bare')).toBeGreaterThan(at('S1:sw2'));
  });

  it('puts role-less hosts below their switch', () => {
    const at = (id: string) => r.nodes.find((n) => n.id === id)!.position.y;
    expect(at('S1:h0-0')).toBeGreaterThan(at('S1:sw0'));
  });

  it('sends nodes with no banded neighbour to a lane under everything', () => {
    const at = (id: string) => r.nodes.find((n) => n.id === id)!.position.y;
    const lowestBanded = Math.max(...r.nodes.filter((n) => !n.id.startsWith('loose')).map((n) => n.position.y));
    for (const id of ['loose:0', 'loose:1', 'loose:2']) expect(at(id)).toBeGreaterThan(lowestBanded);
  });

  it('never stacks two nodes on the same spot', () => {
    expect(new Set(r.nodes.map((n) => `${n.position.x},${n.position.y}`)).size).toBe(r.nodes.length);
  });

  it('keeps every link between nodes that are on the map', () => {
    const ids = new Set(r.nodes.map((n) => n.id));
    expect(r.edges.length).toBeGreaterThan(0);
    expect(r.edges.every((e) => ids.has(e.source) && ids.has(e.target) && !e.inferred)).toBe(true);
  });

  it('does not touch the input graph', () => {
    const before = JSON.stringify(bandedGraph());
    layoutBands(bandedGraph() as any);
    expect(JSON.stringify(g)).toBe(before);
  });

  it('survives ids with control characters', () => {
    const odd = { nodes: [{ node_id: "device:\u001b'3t@", kind: 'device', net_role: 'BR', hostname: 'a' }, { node_id: 'device:b', kind: 'device', net_role: 'SW', hostname: 'b' }], edges: [{ source: "device:\u001b'3t@", target: 'device:b', type: 'lldp' }] } as any;
    expect(layoutBands(odd).nodes.length).toBe(2);
  });

  it('lays lanes side by side without overlap', () => {
    const laneOf = new Map(g.nodes.map((n: any) => [n.node_id, n.site ?? 'Other']));
    const l = layoutBands(g, { laneOf: laneOf as any, laneOrder: ['S1', 'S2'] });
    const xs = (s: string) => l.nodes.filter((n) => laneOf.get(n.id) === s).map((n) => n.position.x);
    expect(Math.min(...xs('S2'))).toBeGreaterThan(Math.max(...xs('S1')));
    expect(new Set(l.nodes.map((n) => `${n.position.x},${n.position.y}`)).size).toBe(l.nodes.length);
  });
});

describe('layoutGraph dispatch', () => {
  it('uses bands when a node has net_role', () => {
    expect(layoutGraph(g, { showIsp: false }).nodes.length).toBe(g.nodes.length - 2);
  });
});
