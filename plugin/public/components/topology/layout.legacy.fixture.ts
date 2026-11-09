// Synthetic graph without any net_role: used to pin the legacy layout output.
export function legacyGraph() {
  const nodes: any[] = [];
  const edges: any[] = [];
  const dev = (id: string, role: string, ip?: string) =>
    nodes.push({ node_id: id, kind: 'device', hostname: id, role, ip: ip ?? null });
  const host = (id: string, ip?: string) =>
    nodes.push({ node_id: id, kind: 'endpoint', hostname: id, role: 'host', ip: ip ?? null });
  const link = (a: string, b: string) => edges.push({ source: a, target: b, type: 'lldp' });
  dev('device:fw', 'firewall', '10.0.0.1');
  for (let i = 0; i < 3; i++) {
    dev(`device:core${i}`, 'l3-switch', `10.0.${i + 1}.1`);
    link('device:fw', `device:core${i}`);
    for (let j = 0; j < 4; j++) {
      const sw = `device:acc${i}-${j}`;
      dev(sw, 'switch', `10.0.${i + 1}.${j + 10}`);
      link(`device:core${i}`, sw);
      for (let k = 0; k < 5 + j; k++) {
        host(`host:${i}-${j}-${k}`);
        link(sw, `host:${i}-${j}-${k}`);
      }
    }
  }
  link('device:acc0-0', 'device:acc1-0');
  for (let i = 0; i < 6; i++) host(`host:sub${i}`, `10.0.1.${100 + i}`);
  for (let i = 0; i < 9; i++) host(`host:orphan${i}`, `192.168.${i}.5`);
  return { nodes, edges };
}
