/** @jest-environment jsdom */
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import { GraphResponse, VulnerabilitiesDoc } from '../../../common';
import labGraph from '../../../test/fixtures/lab.graph.json';
import labVulns from '../../../test/fixtures/lab.vulnerabilities.json';
import { buildAssetReports, ALL_FILTERS, reportAssets } from '../../lib/report';
import { Dashboard } from './Dashboard';

describe('Dashboard', () => {
  let root: HTMLDivElement;
  beforeEach(() => {
    root = document.createElement('div');
    document.body.appendChild(root);
  });
  afterEach(() => {
    act(() => { ReactDOM.unmountComponentAtNode(root); });
    document.body.innerHTML = '';
  });

  it('renders dashboard panels from the existing scan fixtures without NaN', () => {
    const reports = buildAssetReports(labGraph as unknown as GraphResponse, labVulns as unknown as VulnerabilitiesDoc, null);
    act(() => { ReactDOM.render(<Dashboard reports={reportAssets(reports, ALL_FILTERS)} onSeverityClick={() => undefined} />, root); });
    expect(root.querySelector('[data-test-subj="vmVulnDashboard"]')).not.toBeNull();
    expect(root.textContent).toContain('Top 5 CVEs');
    expect(root.textContent).toContain('Top CVEs by exploitation probability');
    expect(root.querySelectorAll('.vmDashboardBars, .vmDashboardDonut svg')).toHaveLength(4);
    expect(root.textContent).not.toContain('NaN');
  });

  it('shows empty states instead of empty charts for zero findings', () => {
    act(() => { ReactDOM.render(<Dashboard reports={[]} onSeverityClick={() => undefined} />, root); });
    expect(root.querySelectorAll('svg')).toHaveLength(0);
    expect(root.querySelectorAll('p').length).toBeGreaterThan(0);
    expect(root.textContent).not.toContain('NaN');
  });
});
