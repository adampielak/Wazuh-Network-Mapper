import { filterByProject, isProjectTab, projectOfTab, projectTabKey, projectTabs, projectsOf } from './project';
import { filterBySite } from './site';

const n = (id: string, site?: string, projects?: unknown) => ({
  node_id: id,
  kind: 'device',
  hostname: id,
  ...(site ? { site, site_source: 'netbox' } : {}),
  ...(projects !== undefined ? { projects } : {}),
});
const e = (a: string, b: string) => ({ source: a, target: b, type: 'lldp' });

describe('projectsOf', () => {
  it('trims, drops empty and non-string values, dedups', () => {
    expect(projectsOf({ projects: [' P ', 'P', '', 3, null, 'Q'] } as any)).toEqual(['P', 'Q']);
  });
  it('is empty for a missing or malformed field', () => {
    expect(projectsOf({} as any)).toEqual([]);
    expect(projectsOf({ projects: null } as any)).toEqual([]);
    expect(projectsOf({ projects: 'P' } as any)).toEqual([]);
  });
});

describe('projectTabs', () => {
  it('lists every project once, sorted, as prefixed keys', () => {
    const g = { nodes: [n('a', 'X', ['Q', 'P']), n('b', 'X', ['P']), n('c')], edges: [] } as any;
    expect(projectTabs(g)).toEqual([projectTabKey('P'), projectTabKey('Q')]);
  });
  it('is empty without projects', () => {
    expect(projectTabs({ nodes: [n('a', 'X')], edges: [] } as any)).toEqual([]);
  });
  it('keeps a project named like a site apart from the site tab', () => {
    const key = projectTabKey('X');
    expect(key).not.toBe('X');
    expect(isProjectTab(key)).toBe(true);
    expect(isProjectTab('X')).toBe(false);
    expect(projectOfTab(key)).toBe('X');
  });
});

describe('filterByProject', () => {
  // a, b, c in project P on site X (10+ nodes so X has a tab); d outside P on X; y on Y
  const filler = Array.from({ length: 10 }, (_, i) => n(`x${i}`, 'X'));
  const fillerY = Array.from({ length: 10 }, (_, i) => n(`y${i}`, 'Y'));
  const g = {
    nodes: [n('a', 'X', ['P']), n('b', 'X', ['P']), n('c', 'Y', ['P']), n('d', 'X'), ...filler, ...fillerY],
    edges: [e('a', 'b'), e('b', 'c'), e('a', 'd'), e('c', 'y0'), e('d', 'x0'), e('a', 'ghost')],
  } as any;

  it('keeps members and the edges between them only', () => {
    const v = filterByProject(g, projectTabKey('P'));
    expect(v.graph.nodes.map((x: any) => x.node_id)).toEqual(['a', 'b', 'c']);
    expect(v.graph.edges).toEqual([e('a', 'b'), e('b', 'c')]);
  });
  it('lists links to non-members by the site tab of the peer', () => {
    const v = filterByProject(g, projectTabKey('P'));
    expect(v.cross.get('a')).toEqual([{ tab: 'X', peers: ['d'] }]);
    expect(v.cross.get('c')).toEqual([{ tab: 'Y', peers: ['y0'] }]);
    expect(v.cross.has('b')).toBe(false);
    expect(v.crossEdges).toBe(2);
  });
  it('ignores edges to nodes missing from the graph', () => {
    const v = filterByProject(g, projectTabKey('P'));
    expect(v.graph.edges.some((x: any) => x.target === 'ghost')).toBe(false);
  });
  it('does not take members off their site tab', () => {
    const site = filterBySite(g, 'X');
    expect(site.graph.nodes.map((x: any) => x.node_id)).toEqual(expect.arrayContaining(['a', 'b', 'd']));
  });
  it('keeps graph metadata', () => {
    const v = filterByProject({ ...g, generated_at: 't' }, projectTabKey('P'));
    expect((v.graph as any).generated_at).toBe('t');
  });
  it('is empty for an unknown project', () => {
    const v = filterByProject(g, projectTabKey('Z'));
    expect(v.graph.nodes).toEqual([]);
    expect(v.crossEdges).toBe(0);
  });
});
