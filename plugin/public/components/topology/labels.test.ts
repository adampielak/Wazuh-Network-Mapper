import { displayName, displaySubtitle, isPlaceholderName } from './labels';

const base = { node_id: 'device:x1', hostname: null, ip: null, mac: null, vendor: null };

describe('isPlaceholderName', () => {
  it.each(['(none)', '(none).(none)', '(none).(none).(none)', 'localhost', ' LocalHost ', '', '   ', ' (none) . (none) '])(
    'treats %j as no name',
    (v) => expect(isPlaceholderName(v)).toBe(true)
  );
  it('treats null and undefined as no name', () => {
    expect(isPlaceholderName(null)).toBe(true);
    expect(isPlaceholderName(undefined)).toBe(true);
  });
  it.each(['sw-01', 'host.example.test', 'none', 'a.(none)'])('keeps %j', (v) =>
    expect(isPlaceholderName(v)).toBe(false)
  );
});

describe('displayName', () => {
  it('prefers a real hostname', () => {
    expect(displayName({ ...base, hostname: 'sw-01', ip: '192.0.2.1' })).toBe('sw-01');
  });
  it('falls back to the IP for a placeholder hostname, with the vendor as subtitle', () => {
    const n = { ...base, hostname: '(none).(none)', ip: '192.0.2.7', vendor: 'ExampleVendor' };
    expect(displayName(n)).toBe('192.0.2.7');
    expect(displaySubtitle(n)).toBe('ExampleVendor');
  });
  it('uses the vendor and the last three MAC octets without an IP', () => {
    const n = { ...base, hostname: '', mac: 'aa:bb:cc:dd:ee:0f', vendor: 'ExampleVendor' };
    expect(displayName(n)).toBe('ExampleVendor dd:ee:0f');
    expect(displaySubtitle(n)).toBeNull();
  });
  it('uses the MAC tail alone when the vendor is unknown', () => {
    expect(displayName({ ...base, mac: 'AA-BB-CC-DD-EE-0F' })).toBe('dd:ee:0f');
  });
  it('ends at the node id', () => {
    expect(displayName({ ...base, hostname: 'localhost' })).toBe('device:x1');
  });
  it('never returns a (none) label', () => {
    expect(displayName({ ...base, hostname: '(none).(none)' })).not.toMatch(/\(none\)/);
  });
  it('has no subtitle for a real hostname', () => {
    expect(displaySubtitle({ ...base, hostname: 'sw-01', ip: '192.0.2.1', vendor: 'V' })).toBeNull();
  });
});
