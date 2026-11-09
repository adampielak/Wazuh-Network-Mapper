// Synthetic banded graph for tests: two sites, every role, role-less hosts.
export function bandedGraph() {
  const nodes: any[] = [];
  const edges: any[] = [];
  const dev = (id: string, site: string, role: string | null, hostname = id) =>
    nodes.push({
      node_id: id,
      kind: 'device',
      hostname,
      ip: null,
      role: 'switch',
      site,
      site_source: 'netbox',
      ...(role ? { net_role: role, net_role_source: 'netbox' } : {}),
    });
  const host = (id: string, hostname: string | null = id) =>
    nodes.push({ node_id: id, kind: 'endpoint', hostname, ip: null, mac: null, vendor: null, role: 'host' });
  const link = (a: string, b: string) => edges.push({ source: a, target: b, type: 'lldp' });

  for (const s of ['S1', 'S2']) {
    dev(`${s}:isp`, s, 'ISP');
    dev(`${s}:br0`, s, 'BR');
    dev(`${s}:br1`, s, 'BR');
    link(`${s}:isp`, `${s}:br0`);
    for (let i = 0; i < 2; i++) {
      dev(`${s}:sp${i}`, s, 'SP');
      link(`${s}:br${i}`, `${s}:sp${i}`);
      link(`${s}:br${i}`, `${s}:sp${1 - i}`);
    }
    for (let i = 0; i < 3; i++) {
      dev(`${s}:lf${i}`, s, 'LF');
      link(`${s}:sp0`, `${s}:lf${i}`);
      link(`${s}:sp1`, `${s}:lf${i}`);
      dev(`${s}:sw${i}`, s, 'SW');
      link(`${s}:lf${i}`, `${s}:sw${i}`);
      dev(`${s}:mgt${i}`, s, 'MGT');
      link(`${s}:lf${i}`, `${s}:mgt${i}`);
      for (let k = 0; k < 4; k++) {
        host(`${s}:h${i}-${k}`);
        link(`${s}:sw${i}`, `${s}:h${i}-${k}`);
      }
    }
    link(`${s}:mgt0`, `${s}:mgt1`);
    link(`${s}:sw0`, `${s}:sw1`);
    dev(`${s}:srv`, s, 'SRV');
    link(`${s}:sw2`, `${s}:srv`);
    link(`${s}:mgt2`, `${s}:srv`);
    dev(`${s}:bare`, s, null);
    link(`${s}:sw2`, `${s}:bare`);
    link(`${s}:mgt1`, `${s}:bare`);
  }
  // an isolated role-less node and a role-less pair with no banded neighbour
  host('loose:0', '(none).(none)');
  host('loose:1');
  host('loose:2');
  link('loose:1', 'loose:2');
  link('S1:br0', 'S2:br0');
  return { nodes, edges };
}
