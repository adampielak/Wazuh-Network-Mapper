import React from 'react';
import { EuiBadge, EuiInMemoryTable, EuiPanel, EuiText, EuiTitle } from '@elastic/eui';
import { AssetReport, Severity, SEVERITIES } from '../../lib/report';
import { DashboardStats, DashboardTop, dashboardStats } from '../../lib/vulnDashboard';
import { SEV_META } from './format';

const LABELS: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'No CVSS score' };
const percent = (value: number, total: number) => total ? `${((value / total) * 100).toFixed(1)}%` : '0.0%';

function Empty() {
  return <EuiText size="xs" color="subdued"><p>No findings</p></EuiText>;
}

function Panel({ title, children, className = '' }: { title: string; children: React.ReactNode; className?: string }) {
  return <EuiPanel paddingSize="m" hasBorder className={`vmDashboardPanel ${className}`}><EuiTitle size="xxs"><h3>{title}</h3></EuiTitle>{children}</EuiPanel>;
}

function TopTable({ title, rows }: { title: string; rows: DashboardTop[] }) {
  return <Panel title={title} className="vmDashboardTopPanel">
    {rows.length ? <table className="vmTable vmDashboardTop"><thead><tr><th>Name</th><th>Count</th></tr></thead><tbody>
      {rows.map((row) => <tr key={row.name}><td title={row.name}>{row.name}</td><td>{row.count}</td></tr>)}
    </tbody></table> : <Empty />}
  </Panel>;
}

function SeverityDonut({ stats }: { stats: DashboardStats }) {
  const total = stats.findings;
  if (!total) return <Empty />;
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  let consumed = 0;
  return <div className="vmDashboardDonut">
    <svg viewBox="0 0 100 100" role="img" aria-label="Findings by severity">
      <circle className="vmDashboardDonut__track" cx="50" cy="50" r={radius} />
      {SEVERITIES.map((severity) => {
        const value = stats.severity[severity];
        const length = (value / total) * circumference;
        const offset = consumed;
        consumed += length;
        return value ? <circle key={severity} cx="50" cy="50" r={radius} fill="none" stroke={SEV_META[severity].color}
          strokeWidth="16" strokeDasharray={`${length} ${circumference - length}`} strokeDashoffset={-offset} /> : null;
      })}
      <text x="50" y="48" textAnchor="middle" className="vmDashboardDonut__value">{total}</text>
      <text x="50" y="59" textAnchor="middle" className="vmDashboardDonut__label">findings</text>
    </svg>
    <ul className="vmDashboardLegend">{SEVERITIES.filter((s) => stats.severity[s] > 0).map((severity) => <li key={severity}>
      <span className="vmDashboardLegend__dot" style={{ backgroundColor: SEV_META[severity].color }} />
      <span>{LABELS[severity]}</span><strong>{stats.severity[severity]} ({percent(stats.severity[severity], total)})</strong>
    </li>)}</ul>
  </div>;
}

function Bars({ labels, values, colors, ariaLabel }: { labels: string[]; values: number[]; colors: string[]; ariaLabel: string }) {
  if (!values.some((v) => v > 0)) return <Empty />;
  const max = Math.max(...values, 1);
  const width = 560;
  const height = 190;
  const left = 30;
  const bottom = 38;
  const chartHeight = height - bottom - 18;
  const slot = (width - left - 8) / values.length;
  const barWidth = Math.max(2, slot * 0.68);
  return <svg className="vmDashboardBars" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={ariaLabel}>
    {values.map((value, index) => {
      const barHeight = (value / max) * chartHeight;
      const x = left + index * slot + (slot - barWidth) / 2;
      const y = height - bottom - barHeight;
      return <g key={labels[index]}>
        <rect x={x} y={y} width={barWidth} height={barHeight} fill={colors[index] || 'var(--vm-dashboard-bar)'} rx="2" />
        <text x={x + barWidth / 2} y={Math.max(12, y - 4)} textAnchor="middle" className="vmDashboardBars__value">{value}</text>
        <text x={x + barWidth / 2} y={height - 16} textAnchor="middle" className="vmDashboardBars__label">{labels[index]}</text>
      </g>;
    })}
  </svg>;
}

function PublicationYears({ stats }: { stats: DashboardStats }) {
  if (!stats.years.length) return <><Empty /><EuiText size="xs" color="subdued"><p>Unknown publication date: {stats.unknownPublicationDate}</p></EuiText></>;
  const max = Math.max(...stats.years.map((y) => SEVERITIES.reduce((n, s) => n + y.counts[s], 0)), 1);
  const width = Math.max(560, stats.years.length * 62);
  const height = 190;
  const bottom = 38;
  const chartHeight = height - bottom - 18;
  const slot = (width - 12) / stats.years.length;
  const barWidth = Math.min(42, slot * 0.7);
  return <>
    <div className="vmDashboardYearScroll"><svg className="vmDashboardBars" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Findings by publication year and severity">
      {stats.years.map(({ year, counts }, index) => {
        const x = index * slot + (slot - barWidth) / 2;
        let y = height - bottom;
        const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
        return <g key={year}>
          {SEVERITIES.map((severity) => {
            const value = counts[severity];
            const barHeight = (value / max) * chartHeight;
            y -= barHeight;
            return value ? <rect key={severity} x={x} y={y} width={barWidth} height={barHeight}
              fill={SEV_META[severity].color} /> : null;
          })}
          <text x={x + barWidth / 2} y={Math.max(12, y - 4)} textAnchor="middle" className="vmDashboardBars__value">{total}</text>
          <text x={x + barWidth / 2} y={height - 16} textAnchor="middle" className="vmDashboardBars__label">{year}</text>
        </g>;
      })}
    </svg></div>
    <EuiText size="xs" color="subdued"><p>Unknown publication date: {stats.unknownPublicationDate}</p></EuiText>
  </>;
}

const cveColumns = [
  { field: 'cve', name: 'CVE', sortable: true },
  { field: 'findings', name: 'Findings', sortable: true, align: 'right' as const },
  { field: 'assets', name: 'Assets', sortable: true, align: 'right' as const },
  { field: 'maxEpss', name: 'Max EPSS', sortable: true, align: 'right' as const, render: (v: number) => v.toFixed(4) },
  { field: 'kev', name: 'KEV', sortable: true, render: (v: boolean) => v ? <EuiBadge color="danger">KEV</EuiBadge> : 'No' },
  { field: 'maxCvss', name: 'Max CVSS', sortable: true, align: 'right' as const, render: (v: number | null) => v === null ? 'No score' : v.toFixed(1) },
];

export function Dashboard({ reports, onSeverityClick }: { reports: AssetReport[]; onSeverityClick: (severity: Severity) => void }) {
  const stats = dashboardStats(reports);
  const tiles = [
    ...SEVERITIES.map((severity) => ({ key: severity, label: LABELS[severity], value: stats.severity[severity], color: severity, severity })),
  ];
  const summaryTiles = [
    ['Findings', `${stats.findings}`], ['Unique CVEs', `${stats.uniqueCves}`], ['Affected assets', `${stats.affectedAssets}`],
    ['CISA KEV findings', `${stats.kevFindings}`], ['EPSS ≥ 0.5 findings', `${stats.epssHighFindings}`], ['Max EPSS', stats.maxEpss.toFixed(4)],
  ];
  const cvssLabels = [...Array.from({ length: 11 }, (_, i) => `${i}`), 'No score'];
  const cvssValues = stats.cvssBuckets;
  const cvssColors = [...Array(11).fill('var(--vm-dashboard-bar)'), SEV_META.unknown.color];
  const epssLabels = Array.from({ length: 10 }, (_, i) => `${(i / 10).toFixed(1)}-${((i + 1) / 10).toFixed(1)}`);

  return <section className="vmDashboard" data-test-subj="vmVulnDashboard" aria-label="Vulnerability dashboard">
    <div className="vmDashboardTiles vmDashboardTiles--severity">{tiles.map((tile) => <button type="button" key={tile.key}
      className={`vmDashboardTile vmDashboardTile--${tile.color}`} onClick={() => onSeverityClick(tile.severity)}
      aria-label={`Filter by ${tile.label}`} data-test-subj={`vmDashboardSeverity-${tile.key}`}>
      <strong>{tile.value}</strong><span>{tile.label}</span>
    </button>)}</div>
    <div className="vmDashboardTiles vmDashboardTiles--summary">{summaryTiles.map(([label, value]) => <div className="vmDashboardTile vmDashboardTile--neutral" key={label}>
      <strong>{value}</strong><span>{label}</span>
    </div>)}</div>

    <div className="vmDashboardTopGrid">
      <TopTable title="Top 5 CVEs" rows={stats.topCves} />
      <TopTable title="Top 5 platforms" rows={stats.topPlatforms} />
      <TopTable title="Top 5 assets" rows={stats.topAssets} />
      <TopTable title="Top 5 packages" rows={stats.topPackages} />
    </div>

    <div className="vmDashboardChartGrid">
      <Panel title="Findings by severity"><SeverityDonut stats={stats} /></Panel>
      <Panel title="EPSS score distribution"><Bars labels={epssLabels} values={stats.epssBuckets} colors={stats.epssBuckets.map(() => 'var(--vm-dashboard-bar)')} ariaLabel="EPSS score distribution" /></Panel>
      <Panel title="Findings per CVSS score"><Bars labels={cvssLabels} values={cvssValues} colors={cvssColors} ariaLabel="Findings by CVSS score" /></Panel>
      <Panel title="Findings by publication year"><PublicationYears stats={stats} /></Panel>
    </div>

    <Panel title="Top CVEs by exploitation probability" className="vmDashboardCvePanel">
      {stats.cveRows.length ? <EuiInMemoryTable
        items={stats.cveRows}
        columns={cveColumns}
        sorting={{ sort: { field: 'maxEpss', direction: 'desc' } }}
        pagination={{ pageSize: 20, pageSizeOptions: [10, 20, 50] }}
        data-test-subj="vmDashboardCveTable"
      /> : <Empty />}
    </Panel>
  </section>;
}
