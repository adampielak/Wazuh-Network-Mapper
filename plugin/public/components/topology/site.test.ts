import { filterBySite, normalizeSavedTab, siteOf, siteTabs, tabOf } from './site';
import { bandedGraph } from './bands.fixture';

const n = (id: string, site?: string, source?: string) => ({
  node_id: id,
  kind: 'device',
  hostname: id,
  ...(site ? { site, site_source: source ?? 'netbox' } : {}),
});
const e = (a: string, b: string) => ({ source: a, target: b, type: 'lldp' });

describe('siteOf neighbour inheritance', () => {
  it('migrates the legacy saved All value', () => {
    expect(normalizeSavedTab('All')).toBe('ALL');
    expect(normalizeSavedTab('DC1')).toBe('DC1');
    expect(normalizeSavedTab(null)).toBeNull();
  });
  it('inherits when all classified neighbours agree', () => {
    const g = { nodes: [n('a', 'X'), n('b', 'X'), n('c')], edges: [e('a', 'c'), e('b', 'c')] } as any;
    expect(siteOf(g).get('c')).toEqual({ site: 'X', source: 'neighbour' });
  });
  it('goes to Other when neighbours disagree', () => {
    const g = { nodes: [n('a', 'X'), n('b', 'Y'), n('c')], edges: [e('a', 'c'), e('b', 'c')] } as any;
    expect(siteOf(g).get('c')).toEqual({ site: 'Other', source: null });
  });
  it('goes to Other with no classified neighbour', () => {
    const g = { nodes: [n('a'), n('c')], edges: [e('a', 'c')] } as any;
    expect(siteOf(g).get('c')?.site).toBe('Other');
  });
  it('does not chain: inherited values are not seeds', () => {
    const g = { nodes: [n('a', 'X'), n('b'), n('c')], edges: [e('a', 'b'), e('b', 'c')] } as any;
    expect(siteOf(g).get('b')?.source).toBe('neighbour');
    expect(siteOf(g).get('c')?.site).toBe('Other');
  });
  it('keeps an own site and its source', () => {
    const g = { nodes: [n('a', 'X', 'zabbix'), n('b', 'Y')], edges: [e('a', 'b')] } as any;
    expect(siteOf(g).get('a')).toEqual({ site: 'X', source: 'zabbix' });
  });
});

describe('siteTabs and filterBySite on the banded fixture', () => {
  const g = bandedGraph() as any;

  it('places unclassified nodes in Other and keeps ALL last', () => {
    expect(siteTabs({ nodes: [n('a')], edges: [] } as any)).toEqual(['Other', 'ALL']);
  });

  it('uses fixed site tabs without the node threshold', () => {
    const graph = { nodes: [n('a', 'DC1'), n('b', 'SB'), n('c', 'DC2')], edges: [] } as any;
    expect(siteTabs(graph)).toEqual(['DC1', 'DC2', 'SB', 'ALL']);
  });

  it('sends every non-fixed site to Other regardless of count', () => {
    const graph = { nodes: [...Array.from({ length: 12 }, (_, i) => n(`a${i}`, 'Z')), n('z', 'DC1')], edges: [] } as any;
    expect(siteTabs(graph)).toEqual(['DC1', 'Other', 'ALL']);
    expect(tabOf(siteOf(graph)).get('a0')).toBe('Other');
  });

  it('only hides fixed tabs that have no nodes', () => {
    const graph = { nodes: [n('a', 'D10')], edges: [] } as any;
    expect(siteTabs(graph)).toEqual(['D10', 'ALL']);
  });

  it('partitions the nodes over the tabs', () => {
    const tabs = siteTabs(g).filter((t) => t !== 'ALL');
    const total = tabs.reduce((s, t) => s + filterBySite(g, t, 10).graph.nodes.length, 0);
    expect(total).toBe(g.nodes.length);
  });

  it('badges both ends of a link into another tab', () => {
    const graph = { nodes: [n('a', 'DC1'), n('b', 'DC2')], edges: [e('a', 'b')] } as any;
    const v1 = filterBySite(graph, 'DC1');
    const v2 = filterBySite(graph, 'DC2');
    expect(v1.crossEdges).toBe(1);
    expect(v1.cross.get('a')).toEqual([{ tab: 'DC2', peers: ['b'] }]);
    expect(v2.cross.get('b')).toEqual([{ tab: 'DC1', peers: ['a'] }]);
    expect(v1.graph.edges).toEqual([]);
  });

  it('keeps the whole graph on ALL', () => {
    const v = filterBySite(g, 'ALL');
    expect(v.graph).toBe(g);
    expect(v.cross.size).toBe(0);
  });
});
