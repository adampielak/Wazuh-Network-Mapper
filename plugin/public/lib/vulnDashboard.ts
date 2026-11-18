import { AssetReport, SEVERITIES, Severity } from './report';

export type DashboardTop = { name: string; count: number };
export type DashboardCve = {
  cve: string;
  findings: number;
  assets: number;
  maxEpss: number;
  kev: boolean;
  maxCvss: number | null;
};
export type DashboardYear = { year: string; counts: Record<Severity, number> };
export type DashboardStats = {
  severity: Record<Severity, number>;
  findings: number;
  uniqueCves: number;
  affectedAssets: number;
  kevFindings: number;
  epssHighFindings: number;
  maxEpss: number;
  topCves: DashboardTop[];
  topPlatforms: DashboardTop[];
  topAssets: DashboardTop[];
  topPackages: DashboardTop[];
  epssBuckets: number[];
  cvssBuckets: number[];
  years: DashboardYear[];
  unknownPublicationDate: number;
  cveRows: DashboardCve[];
};

const emptySeverity = (): Record<Severity, number> => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
const compareCodePoints = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const finiteNumber = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
const emptyStats = (): DashboardStats => ({
  severity: emptySeverity(), findings: 0, uniqueCves: 0, affectedAssets: 0, kevFindings: 0,
  epssHighFindings: 0, maxEpss: 0, topCves: [], topPlatforms: [], topAssets: [], topPackages: [],
  epssBuckets: Array(10).fill(0), cvssBuckets: Array(12).fill(0), years: [], unknownPublicationDate: 0, cveRows: [],
});
const top = (counts: Map<string, number>) => [...counts.entries()]
  .map(([name, count]) => ({ name, count }))
  .sort((a, b) => b.count - a.count || compareCodePoints(a.name, b.name))
  .slice(0, 5);

/** Aggregate only findings present in the already-filtered asset reports. */
export function dashboardStats(reports: AssetReport[]): DashboardStats {
  const stats = emptyStats();
  const cves = new Map<string, DashboardCve>();
  const cveAssets = new Map<string, Set<string>>();
  const platforms = new Map<string, number>();
  const packages = new Map<string, number>();
  const years = new Map<string, Record<Severity, number>>();

  for (const report of reports) {
    if (!report.cves.length) continue;
    stats.affectedAssets += 1;
    for (const finding of report.cves) {
      const severity = SEVERITIES.includes(finding.severity as Severity) ? finding.severity as Severity : 'unknown';
      stats.findings += 1;
      stats.severity[severity] += 1;
      const epss = Math.max(0, Math.min(1, finiteNumber(finding.epss) ? finding.epss : 0));
      stats.maxEpss = Math.max(stats.maxEpss, epss);
      if (finding.kev) stats.kevFindings += 1;
      if (epss >= 0.5) stats.epssHighFindings += 1;
      stats.epssBuckets[Math.min(9, Math.floor(epss * 10))] += 1;
      if (!finiteNumber(finding.cvss)) stats.cvssBuckets[11] += 1;
      else stats.cvssBuckets[Math.max(0, Math.min(10, Math.floor(finding.cvss)))] += 1;
      if (finding.package) packages.set(finding.package, (packages.get(finding.package) || 0) + 1);
      const platform = report.node.vendor || 'Unknown';
      platforms.set(platform, (platforms.get(platform) || 0) + 1);

      let row = cves.get(finding.cve);
      if (!row) {
        row = { cve: finding.cve, findings: 0, assets: 0, maxEpss: 0, kev: false, maxCvss: null };
        cves.set(finding.cve, row);
        cveAssets.set(finding.cve, new Set());
      }
      row.findings += 1;
      row.maxEpss = Math.max(row.maxEpss, epss);
      row.kev = row.kev || !!finding.kev;
      if (finiteNumber(finding.cvss)) row.maxCvss = row.maxCvss === null ? finding.cvss : Math.max(row.maxCvss, finding.cvss);
      cveAssets.get(finding.cve)!.add(report.id);

      const year = finding.published_at && /^\d{4}/.test(finding.published_at)
        ? finding.published_at.slice(0, 4)
        : null;
      if (year) {
        if (!years.has(year)) years.set(year, emptySeverity());
        years.get(year)![severity] += 1;
      } else {
        stats.unknownPublicationDate += 1;
      }
    }
  }

  for (const [cve, row] of cves) row.assets = cveAssets.get(cve)!.size;
  stats.uniqueCves = cves.size;
  stats.topCves = top(new Map([...cves].map(([name, row]) => [name, row.assets])));
  stats.topPlatforms = top(platforms);
  stats.topAssets = reports.filter((report) => report.cves.length > 0)
    .slice()
    .sort((a, b) => b.cves.length - a.cves.length || compareCodePoints(a.name, b.name) || compareCodePoints(a.id, b.id))
    .slice(0, 5)
    .map((report) => ({ name: report.name, count: report.cves.length }));
  stats.topPackages = top(packages);
  stats.years = [...years.entries()].sort(([a], [b]) => compareCodePoints(a, b)).map(([year, counts]) => ({ year, counts }));
  stats.cveRows = [...cves.values()].sort((a, b) => compareCodePoints(a.cve, b.cve));
  return stats;
}
