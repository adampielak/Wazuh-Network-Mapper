import { filterBySite, siteOf, siteTabs, tabOf } from './site';
import { bandedGraph } from './bands.fixture';

const n = (id: string, site?: string, source?: string) => ({
  node_id: id,
  kind: 'device',
  hostname: id,
  ...(site ? { site, site_source: source ?? 'netbox' } : {}),
});
const e = (a: string, b: string) => ({ source: a, target: b, type: 'lldp' });

describe('siteOf neighbour inheritance', () => {
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

  it('has no tabs without any site', () => {
    expect(siteTabs({ nodes: [n('a')], edges: [] } as any)).toEqual([]);
  });

  it('lists sites with enough nodes, Other, then All', () => {
    const tabs = siteTabs(g, 10);
    expect(tabs.slice(0, 2)).toEqual(['S1', 'S2']);
    expect(tabs[tabs.length - 1]).toBe('All');
    expect(tabs).toContain('Other');
  });

  it('sends small sites to Other', () => {
    const small = { nodes: [...Array.from({ length: 10 }, (_, i) => n(`a${i}`, 'DC1')), n('z', 'Z')], edges: [] } as any;
    expect(siteTabs(small, 10)).toEqual(['DC1', 'Other', 'All']);
    expect(tabOf(siteOf(small), 10).get('z')).toBe('Other');
  });

  it('orders DC sites numerically ahead of the others', () => {
    const mk = (s: string) => Array.from({ length: 10 }, (_, i) => n(`${s}${i}`, s));
    const o = { nodes: [...mk('SB'), ...mk('DC2'), ...mk('D10'), ...mk('DC1')], edges: [] } as any;
    expect(siteTabs(o, 10)).toEqual(['DC1', 'DC2', 'D10', 'SB', 'All']);
  });

  it('partitions the nodes over the tabs', () => {
    const tabs = siteTabs(g, 10).filter((t) => t !== 'All');
    const total = tabs.reduce((s, t) => s + filterBySite(g, t, 10).graph.nodes.length, 0);
    expect(total).toBe(g.nodes.length);
  });

  it('badges both ends of a link into another tab', () => {
    const v1 = filterBySite(g, 'S1', 10);
    const v2 = filterBySite(g, 'S2', 10);
    expect(v1.crossEdges).toBe(1);
    expect(v1.cross.get('S1:br0')).toEqual([{ tab: 'S2', peers: ['S2:br0'] }]);
    expect(v2.cross.get('S2:br0')).toEqual([{ tab: 'S1', peers: ['S1:br0'] }]);
    expect(v1.graph.edges.every((x) => !(x.source.startsWith('S2') || x.target.startsWith('S2')))).toBe(true);
  });

  it('keeps the whole graph on All', () => {
    const v = filterBySite(g, 'All', 10);
    expect(v.graph).toBe(g);
    expect(v.cross.size).toBe(0);
  });
});
