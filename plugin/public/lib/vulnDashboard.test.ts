import { AssetReport, AssetCve, reportAssets, ALL_FILTERS } from './report';
import { dashboardStats } from './vulnDashboard';

const finding = (values: Partial<AssetCve> & Pick<AssetCve, 'cve'>) => ({
  score: null, tier: null, kev: false, epss: 0, cvss_src: null, cvss_ver: null, conflict: null,
  cvss_version: null, severity: 'unknown', description: null, reference: null,
  confidence: 'confirmed', package: null, version: null,
  cvss: null, ...values,
} as AssetCve);

const asset = (id: string, name: string, vendor: string | null, cves: AssetCve[]) => ({
  id, name, node: { vendor }, cves,
  ovss: null, tiers: { P0: 0, P1: 0, P2: 0, P3: 0, Unrated: 0 }, counts: { total: cves.length },
  onPath: false, managed: true, level: 'none', configFindings: [], routesThrough: 0,
} as unknown as AssetReport);

const fixture: AssetReport[] = [
  asset('asset-a', 'alpha.example', 'Acme', [
    finding({ cve: 'CVE-2099-0001', cvss: 8, severity: 'high', epss: 1, kev: true, package: 'pkg-a', published_at: '2024-02-01' }),
    finding({ cve: 'CVE-2099-0002', cvss: null, severity: 'unknown', package: null }),
  ]),
  asset('asset-b', 'beta.example', 'Acme', [
    finding({ cve: 'CVE-2099-0001', cvss: 8, severity: 'high', epss: 0.7, kev: false, package: 'pkg-b', published_at: '2024-11-20' }),
    finding({ cve: 'CVE-2099-0003', cvss: 3.2, severity: 'low', epss: 0.5, package: 'pkg-a', published_at: '2023-05-01' }),
  ]),
];

describe('dashboardStats', () => {
  it('aggregates findings, distinct CVEs, assets, KEV and EPSS buckets including 0 and 1', () => {
    const stats = dashboardStats(fixture);
    expect(stats).toMatchObject({ findings: 4, uniqueCves: 3, affectedAssets: 2, kevFindings: 1, epssHighFindings: 3, maxEpss: 1 });
    expect(stats.severity).toEqual({ critical: 0, high: 2, medium: 0, low: 1, unknown: 1 });
    expect(stats.epssBuckets[0]).toBe(1);
    expect(stats.epssBuckets[5]).toBe(1);
    expect(stats.epssBuckets[7]).toBe(1);
    expect(stats.epssBuckets[9]).toBe(1);
    expect(stats.cvssBuckets[8]).toBe(2);
    expect(stats.cvssBuckets[3]).toBe(1);
    expect(stats.cvssBuckets[11]).toBe(1);
  });

  it('stacks publication years by severity and tracks missing dates separately', () => {
    const stats = dashboardStats(fixture);
    expect(stats.years).toEqual([
      { year: '2023', counts: { critical: 0, high: 0, medium: 0, low: 1, unknown: 0 } },
      { year: '2024', counts: { critical: 0, high: 2, medium: 0, low: 0, unknown: 0 } },
    ]);
    expect(stats.unknownPublicationDate).toBe(1);
  });

  it('breaks top-five ties by name and skips null packages', () => {
    const tied = dashboardStats([
      asset('asset-z', 'zeta.example', null, [finding({ cve: 'CVE-2099-0004', package: 'same' })]),
      asset('asset-a', 'alpha.example', null, [finding({ cve: 'CVE-2099-0005', package: 'same' })]),
    ]);
    expect(tied.topAssets.map((row) => row.name)).toEqual(['alpha.example', 'zeta.example']);
    expect(tied.topPlatforms).toEqual([{ name: 'Unknown', count: 2 }]);
    expect(tied.topPackages).toEqual([{ name: 'same', count: 2 }]);
    expect(tied.topCves.map((row) => row.name)).toEqual(['CVE-2099-0004', 'CVE-2099-0005']);
  });

  it('aggregates CVE rows with unique asset counts and maximum values', () => {
    expect(dashboardStats(fixture).cveRows.find((row) => row.cve === 'CVE-2099-0001')).toEqual({
      cve: 'CVE-2099-0001', findings: 2, assets: 2, maxEpss: 1, kev: true, maxCvss: 8,
    });
  });

  it('uses reports filtered by the applied report filters', () => {
    const reports = fixture.map((r) => ({ ...r, onPath: r.id === 'asset-a' }));
    const filtered = reportAssets(reports, { ...ALL_FILTERS, severities: ['high'], onPath: true });
    expect(dashboardStats(filtered)).toMatchObject({ findings: 1, uniqueCves: 1, affectedAssets: 1, kevFindings: 1 });
  });
});
