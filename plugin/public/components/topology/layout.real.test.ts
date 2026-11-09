// Acceptance checks on a real graph. Carries no data: it runs only when the
// environment variable GRAPH_JSON points to a graph.json whose nodes already
// hold site / net_role, and is skipped otherwise.
import * as fs from 'fs';
import { bandOf, bandRowCapacity, withoutIsp } from './bands';
import { displayName } from './labels';
import { layoutGraph, PEND_COLS_MAX } from './layout';
import { ALL_SITES, OTHER_SITE, filterBySite, siteOf, siteTabs, tabOf } from './site';

(globalThis as any).structuredClone ??= (v: unknown) => JSON.parse(JSON.stringify(v));

const file = process.env.GRAPH_JSON;
const suite = file ? describe : describe.skip;
const SOURCES = new Set(['netbox', 'zabbix', 'name', 'neighbour']);

suite('banded topology on a real graph', () => {
  const graph: any = file ? JSON.parse(fs.readFileSync(file, 'utf8')) : { nodes: [], edges: [] };
  const visible = withoutIsp(graph);
  const info = siteOf(visible);
  const tabOfNode = tabOf(info);
  const tabs = siteTabs(visible);
  const siteTabNames = tabs.filter((t) => t !== ALL_SITES);
  const views = new Map(tabs.map((t) => [t, filterBySite(visible, t)]));
  const lay = (t: string, showIsp = false) => {
    const src = showIsp ? graph : visible;
    const v = filterBySite(src, t);
    const laneOf = t === ALL_SITES ? tabOf(siteOf(src)) : undefined;
    return layoutGraph(v.graph, { showIsp, laneOf, laneOrder: siteTabNames });
  };
  const report: string[] = [];
  afterAll(() => {
    if (process.env.VERBOSE) console.log(report.join('\n'));
  });

  it('1. tabs partition the visible nodes and only add to source-classified counts', () => {
    const sum = siteTabNames.reduce((s, t) => s + views.get(t)!.graph.nodes.length, 0);
    expect(sum).toBe(visible.nodes.length);
    for (const t of siteTabNames.filter((x) => x !== OTHER_SITE)) {
      const given = visible.nodes.filter((n: any) => n.site === t && SOURCES.has(n.site_source)).length;
      expect(views.get(t)!.graph.nodes.length).toBeGreaterThanOrEqual(given);
    }
    report.push(`tabs: ${siteTabNames.map((t) => `${t}=${views.get(t)!.graph.nodes.length}`).join(' ')} (graph ${graph.nodes.length}, ISP ${graph.nodes.length - visible.nodes.length})`);
  });

  it('2. BR is the top row of every tab, ISP above it when shown', () => {
    for (const t of tabs) {
      const r = lay(t);
      const br = r.nodes.filter((n) => n.data.net_role === 'BR').map((n) => n.position.y);
      if (!br.length) continue;
      const lane = (id: string) => (t === ALL_SITES ? tabOfNode.get(id) : t);
      for (const l of new Set(r.nodes.map((n) => lane(n.id)))) {
        const mine = r.nodes.filter((n) => lane(n.id) === l);
        const own = mine.filter((n) => n.data.net_role === 'BR').map((n) => n.position.y);
        if (own.length) {
          expect(new Set(own).size).toBe(1);
          expect(Math.min(...own)).toBe(Math.min(...mine.map((n) => n.position.y)));
        }
      }
      report.push(`BR ${t}: ${br.length} nodes, y=${[...new Set(br)].join(',')}`);
      const s = lay(t, true);
      const isp = s.nodes.filter((n) => n.data.net_role === 'ISP');
      for (const i of isp) {
        const same = s.nodes.filter((n) => n.data.net_role === 'BR' && (t === ALL_SITES ? tabOf(siteOf(graph)).get(n.id) === tabOf(siteOf(graph)).get(i.id) : true));
        for (const b of same) expect(i.position.y).toBeLessThan(b.position.y);
      }
    }
  });

  it('3. classified bands are strictly ordered in every tab', () => {
    for (const t of siteTabNames) {
      const r = lay(t);
      for (let k = 0; k < 4; k++) {
        const upper = r.nodes.filter((n) => bandOf(n.data.net_role) === k).map((n) => n.position.y);
        const lower = r.nodes.filter((n) => bandOf(n.data.net_role) === k + 1).map((n) => n.position.y);
        if (upper.length && lower.length) expect(Math.min(...lower)).toBeGreaterThan(Math.max(...upper));
      }
    }
  });

  it('4. no (none) in any visible label', () => {
    const labels = graph.nodes.map((n: any) => displayName(n));
    expect(labels.filter((l: string) => /\(none\)/.test(l))).toEqual([]);
    const placeholders = graph.nodes.filter((n: any) => /\(none\)/.test(n.hostname || ''));
    report.push(`placeholder hostnames: ${placeholders.length}, shown as ip: ${placeholders.filter((n: any) => displayName(n) === n.ip).length}`);
  });

  it('5. no overlap, aspect ratio under 6', () => {
    for (const t of tabs) {
      const r = lay(t);
      expect(new Set(r.nodes.map((n) => `${n.position.x},${n.position.y}`)).size).toBe(r.nodes.length);
      const xs = r.nodes.map((n) => n.position.x);
      const ys = r.nodes.map((n) => n.position.y);
      const ratio = (Math.max(...xs) - Math.min(...xs)) / (Math.max(...ys) - Math.min(...ys) || 1);
      const rows = new Map<string, number>();
      // a row is counted per lane: swimlanes share y but are separate lines
      for (const n of r.nodes) {
        const key = `${t === ALL_SITES ? tabOfNode.get(n.id) : ''}|${n.position.y}`;
        rows.set(key, (rows.get(key) || 0) + 1);
      }
      const widest = Math.max(...rows.values());
      report.push(`layout ${t}: ${r.nodes.length} nodes, aspect ${ratio.toFixed(2)}, widest row ${widest} (capacity ${bandRowCapacity(r.nodes.length)})`);
      expect(ratio).toBeLessThan(6);
      expect(widest).toBeLessThanOrEqual(Math.max(bandRowCapacity(r.nodes.length), PEND_COLS_MAX));
    }
  });

  it('6. every source tag is a known one', () => {
    for (const n of graph.nodes) {
      for (const v of [n.site_source, n.net_role_source]) expect(v == null || SOURCES.has(v)).toBe(true);
    }
    for (const { source } of info.values()) expect(source == null || SOURCES.has(source)).toBe(true);
  });

  it('7. every cross-tab link badges both ends and All draws it', () => {
    const total = views.get(siteTabNames[0])!.crossEdges;
    const badged = siteTabNames.reduce((s, t) => s + [...views.get(t)!.cross.values()].reduce((a, l) => a + l.reduce((b, x) => b + x.peers.length, 0), 0), 0);
    expect(badged).toBe(2 * total);
    const all = lay(ALL_SITES);
    const ids = new Set(all.nodes.map((n) => n.id));
    const crossDrawn = all.edges.filter((e) => tabOfNode.get(e.source) !== tabOfNode.get(e.target));
    expect(crossDrawn.length).toBe(total);
    expect(crossDrawn.every((e) => ids.has(e.source) && ids.has(e.target))).toBe(true);
    const withIsp = filterBySite(graph, siteTabNames[0]).crossEdges;
    report.push(`cross-site edges: ${total} with ISP hidden, ${withIsp} with ISP shown`);
  });
});
