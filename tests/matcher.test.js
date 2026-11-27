import { describe, expect, it } from 'vitest'
import { analyze, normalize, normalizeLine, catalog, appliesTo, cmpVersion } from '../src/matcher.js'

const SUBSYSTEMS = [
  'raft', 'storage', 'seal', 'auth', 'pki', 'transit', 'replication', 'audit',
  'token', 'identity', 'tls', 'ha', 'network',
]

const top = (text, n = 1) => analyze(text, { limit: n }).map((r) => r.entry.id)

describe('normalize', () => {
  it('strips ANSI codes, timestamps and hclog levels', () => {
    const line = '\x1b[31m2024-05-01T12:00:00.123Z [ERROR] core: failed to unseal\x1b[0m'
    expect(normalizeLine(line)).toBe('core: failed to unseal')
  })

  it('strips syslog/journald prefixes', () => {
    expect(normalizeLine('Nov 26 16:52:01 vault-0 vault[1234]: 2024-11-26T16:52:01.000Z [WARN]  storage.raft: heartbeat timeout reached'))
      .toBe('storage.raft: heartbeat timeout reached')
  })

  it('strips logfmt timestamp and level keys', () => {
    expect(normalizeLine('level=error time=2024-01-02T03:04:05Z msg="x"')).toBe('msg="x"')
  })

  it('strips logfmt keys when time= comes before level=', () => {
    expect(normalizeLine('time=2024-01-02T03:04:05Z level=error expiration: failed to revoke lease'))
      .toBe('expiration: failed to revoke lease')
  })

  it('keeps a leading "Error" word that is not a log level', () => {
    expect(normalizeLine('Error initializing listener of type tcp: listen tcp4 0.0.0.0:443: bind: permission denied'))
      .toBe('Error initializing listener of type tcp: listen tcp4 0.0.0.0:443: bind: permission denied')
  })

  it('strips lowercase colon-terminated levels', () => {
    expect(normalizeLine('error: expiration: failed to revoke lease')).toBe('expiration: failed to revoke lease')
  })

  it('drops blank lines', () => {
    expect(normalize('\n  \nfoo\n\n')).toEqual(['foo'])
  })
})

describe('catalog', () => {
  it('never recommends prefix force-revokes, role-replacing writes, or unconditional raft wipes', () => {
    const cmds = catalog.entries.flatMap((e) => e.troubleshooting_steps.map((st) => st.command || ''))
    expect(cmds.filter((c) => /lease revoke -force -prefix <(mount|path)/.test(c))).toEqual([])
    expect(cmds.filter((c) => /lease revoke -force(?! -prefix)/.test(c))).toEqual([])
    expect(cmds.filter((c) => /vault write \S+\/roles\//.test(c))).toEqual([])
    expect(cmds.filter((c) => /diff <\(openssl/.test(c))).toEqual([])
  })

  it('has 50-100 entries with unique ids', () => {
    const ids = catalog.entries.map((e) => e.id)
    expect(ids.length).toBeGreaterThanOrEqual(50)
    expect(ids.length).toBeLessThanOrEqual(100)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it.each(catalog.entries.map((e) => [e.id, e]))('%s is well formed', (_id, e) => {
    expect(SUBSYSTEMS).toContain(e.subsystem)
    expect(['internal', 'external', 'both']).toContain(e.location)
    expect(e.patterns.length).toBeGreaterThan(0)
    e.patterns.forEach((p) => expect(() => new RegExp(p, 'i')).not.toThrow())
    expect(e.summary).toBeTruthy()
    expect(Array.isArray(e.internal_causes)).toBe(true)
    expect(Array.isArray(e.external_causes)).toBe(true)
    expect(e.troubleshooting_steps.length).toBeGreaterThan(0)
    expect(e.references.length).toBeGreaterThan(0)
    expect(e.examples.length).toBeGreaterThan(0)
  })

  it.each(catalog.entries.map((e) => [e.id, e]))('%s examples rank it first', (id, e) => {
    for (const ex of e.examples) expect(top(ex)).toEqual([id])
  })
})

describe('version filtering', () => {
  it('compares minor versions numerically', () => {
    expect(cmpVersion('1.15', '2.0')).toBeLessThan(0)
    expect(cmpVersion('1.19', '1.9')).toBeGreaterThan(0)
    expect(cmpVersion('2.2', '2.2')).toBe(0)
  })

  it('applies entries without a versions field to every version', () => {
    expect(appliesTo({ id: 'x' }, '1.15')).toBe(true)
    expect(appliesTo({ id: 'x' }, '2.2')).toBe(true)
  })

  it('honours since/until ranges', () => {
    const e = { versions: { since: '1.19' } }
    expect(appliesTo(e, '1.15')).toBe(false)
    expect(appliesTo(e, '1.18')).toBe(false)
    expect(appliesTo(e, '1.19')).toBe(true)
    expect(appliesTo(e, '2.2')).toBe(true)
    const u = { versions: { until: '1.18' } }
    expect(appliesTo(u, '1.18')).toBe(true)
    expect(appliesTo(u, '1.19')).toBe(false)
  })

  it('excludes version-mismatched entries from analysis', () => {
    const removed = catalog.entries.find((e) => e.id === 'raft-node-removed')
    expect(removed.versions.since).toBe('1.19')
    const text = removed.examples[0]
    expect(analyze(text, { vaultVersion: '1.15' }).map((r) => r.entry.id)).not.toContain('raft-node-removed')
    expect(top(text, 3)).toContain('raft-node-removed')  // default: no version filtering
  })

  it('catalog exposes the supported version list starting at 1.15', () => {
    expect(catalog.vault_versions[0]).toBe('1.15')
    expect(catalog.vault_versions.length).toBeGreaterThanOrEqual(8)
  })

  it('version-tagged entries have well-formed ranges within the supported list', () => {
    const valid = new Set(catalog.vault_versions)
    for (const e of catalog.entries) {
      if (!e.versions) continue
      if (e.versions.since) expect(valid.has(e.versions.since)).toBe(true)
      if (e.versions.until) expect(valid.has(e.versions.until)).toBe(true)
      if (e.versions.since && e.versions.until) {
        expect(cmpVersion(e.versions.since, e.versions.until)).toBeLessThanOrEqual(0)
      }
    }
  })
})

describe('analyze: real-world log lines', () => {
  const cases = [
    ['2024-05-01T10:00:00.000Z [ERROR] core: failed to unseal: error="fetching stored unseal keys failed: failed to decrypt keys from storage: AccessDeniedException: The ciphertext refers to a customer master key that does not exist"', 'seal-awskms'],
    ['Error making API request.\n\nURL: GET https://vault:8200/v1/secret/data/app\nCode: 503. Errors:\n\n* Vault is sealed', 'seal-vault-sealed'],
    ['2024-05-01T10:00:00.000Z [WARN]  storage.raft: heartbeat timeout reached, starting election: last-leader-addr=10.0.0.2:8201 last-leader-id=vault-2', 'raft-heartbeat-election'],
    ['Code: 403. Errors:\n\n* 1 error occurred:\n\t* permission denied', 'token-permission-denied'],
    ['[ERROR] core: error during forwarded RPC request: error="rpc error: code = Unavailable desc = connection error"', 'ha-forwarding-failed'],
    ['Get "https://vault.example.com:8200/v1/sys/health": x509: certificate signed by unknown authority', 'tls-unknown-authority'],
    ['dial tcp 10.0.0.5:8200: connect: connection refused', 'network-connection-refused'],
    ['Error decrypting data: Error making API request.\n\nURL: PUT https://transit:8200/v1/transit/decrypt/autounseal\nCode: 403. Errors:\n\n* permission denied', 'seal-transit'],
  ]

  it.each(cases)('%s -> %s', (log, id) => {
    expect(top(log, 3)).toContain(id)
  })

  it('returns several ranked hits for a multi-error paste', () => {
    const paste = [
      '[ERROR] core: failed to unseal: error="fetching stored unseal keys failed"',
      '[WARN]  storage.raft: heartbeat timeout reached, starting election',
      'x509: certificate signed by unknown authority',
    ].join('\n')
    const results = analyze(paste, { limit: 10 })
    expect(results.length).toBeGreaterThanOrEqual(3)
    for (let i = 1; i < results.length; i++) {
      expect(results[i - 1].confidence).toBeGreaterThanOrEqual(results[i].confidence)
    }
  })

  it('confidence is an integer percentage', () => {
    const [r] = analyze('Vault is sealed')
    expect(Number.isInteger(r.confidence)).toBe(true)
    expect(r.confidence).toBeGreaterThan(0)
    expect(r.confidence).toBeLessThanOrEqual(100)
  })

  it('ranks lowercase "error:" lease revocation timeouts as revocation failures', () => {
    expect(top('error: expiration: failed to revoke lease: lease_id=database/creds/app/abc error="failed to revoke entry: dial tcp 10.0.2.5:5432: i/o timeout"')[0]).toBe('token-revocation-failed')
  })

  it('ranks timestamp-first logfmt lines by logger', () => {
    expect(top('time=2024-01-02T03:04:05Z level=error expiration: failed to revoke lease: lease_id=database/creds/app/abc')[0]).toBe('token-revocation-failed')
  })

  it('ranks multi-line Transit auto-unseal denials above generic token denials', () => {
    expect(top('Error decrypting data: Error making API request.\n\nURL: PUT https://transit:8200/v1/transit/decrypt/autounseal\nCode: 403. Errors:\n\n* permission denied')[0]).toBe('seal-transit')
  })

  it('does not treat an ordinary denied Transit API call as an auto-unseal failure', () => {
    const res = analyze('[INFO]  secrets.transit: key rotated: name=app\nError writing data to transit/encrypt/app: Error making API request.\n\nURL: PUT https://vault:8200/v1/transit/encrypt/app\nCode: 403. Errors:\n\n* permission denied')
    expect(res[0].entry.id).toBe('token-permission-denied')
    const transit = res.find((r) => r.entry.id === 'seal-transit')
    expect(transit?.matchedPatterns ?? []).toEqual([])
  })

  it('ranks an OS-level bind permission error as a listener problem, not a token denial', () => {
    const ids = top('Error initializing listener of type tcp: listen tcp 0.0.0.0:443: bind: permission denied', 5)
    expect(ids[0]).toBe('network-listener-bind')
    expect(ids).not.toContain('token-permission-denied')
  })

  it('does not treat file permission errors as token denials', () => {
    expect(top('error loading TLS cert: open /etc/vault.d/tls/vault.crt: permission denied', 5)).not.toContain('token-permission-denied')
  })

  it('ignores healthy raft startup lines', () => {
    expect(analyze('2024-05-01T10:00:00.000Z [INFO]  storage.raft: initial configuration: index=1 servers="[]"')).toEqual([])
    expect(analyze('[INFO]  storage.raft: entering follower state: follower="Node at 10.0.0.1:8201 [Follower]" leader-address= leader-id=')).toEqual([])
  })

  it('returns no matches for unrelated text', () => {
    expect(analyze('the quick brown fox jumps over the lazy dog')).toEqual([])
    expect(analyze('')).toEqual([])
  })
})

describe('loggerSubsystem', async () => {
  const { loggerSubsystem } = await import('../src/matcher.js')
  it('maps hclog logger names to subsystems', () => {
    expect(loggerSubsystem('storage.raft: heartbeat timeout reached')).toBe('raft')
    expect(loggerSubsystem('expiration: failed to revoke lease')).toBe('token')
    expect(loggerSubsystem('core: failed to unseal')).toBeNull()
    expect(loggerSubsystem('no logger here')).toBeNull()
  })
})
