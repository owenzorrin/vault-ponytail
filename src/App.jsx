import { useMemo, useRef, useState } from 'react'
import { analyze, appliesTo, catalog, VAULT_VERSIONS } from './matcher.js'
import ResultCard from './components/ResultCard.jsx'
import NoMatch from './components/NoMatch.jsx'

const SAMPLE_IDS = [
  'seal-awskms',
  'seal-mlock',
  'seal-hsm-pkcs11',
  'raft-heartbeat-election',
  'raft-lost-quorum',
  'raft-node-removed',
  'storage-dynamodb',
  'storage-consul-lock-lost',
  'storage-readonly',
  'tls-unknown-authority',
  'ha-forwarding-failed',
  'network-listener-bind',
  'token-permission-denied',
  'token-quota-exceeded',
  'auth-kubernetes',
  'auth-approle',
  'pki-crl-build',
  'transit-invalid-ciphertext',
  'audit-device-failed',
  'identity-entity-invalid',
  'replication-connection',
]

const CATALOG_SAMPLES = SAMPLE_IDS
  .map((id) => catalog.entries.find((e) => e.id === id))
  .filter(Boolean)
  .map((e) => ({ id: e.id, title: e.title, subsystem: e.subsystem, versions: e.versions, text: e.examples[0] }))

const SAMPLES = [
  ...CATALOG_SAMPLES,
  {
    id: 'multi-error-incident',
    title: 'Multi-error incident log (3 lines)',
    subsystem: 'multi',
    text: [
      '2024-05-01T10:00:00.000Z [ERROR] core: failed to unseal: error="fetching stored unseal keys failed: failed to decrypt keys from storage: AccessDeniedException: The ciphertext refers to a customer master key that does not exist"',
      '2024-05-01T10:00:02.114Z [WARN]  storage.raft: heartbeat timeout reached, starting election: last-leader-addr=10.0.0.2:8201 last-leader-id=vault-2',
      '2024-05-01T10:00:05.302Z [ERROR] core: error during forwarded RPC request: error="Get \\"https://vault.example.com:8200/v1/sys/health\\": x509: certificate signed by unknown authority"',
    ].join('\n'),
  },
]

const subsystems = new Set(catalog.entries.map((e) => e.subsystem))

function App() {
  const [input, setInput] = useState('')
  const [results, setResults] = useState(null)
  const [limit, setLimit] = useState(5)
  const [runId, setRunId] = useState(0)
  const [vaultVersion, setVaultVersion] = useState(() => VAULT_VERSIONS[VAULT_VERSIONS.length - 1] || null)
  const [sampleFilter, setSampleFilter] = useState('all')
  const analyzedText = useRef(null)

  const applicableSamples = useMemo(
    () => SAMPLES.filter((s) => appliesTo(s, vaultVersion)),
    [vaultVersion],
  )
  const sampleSubsystems = useMemo(
    () => [...new Set(applicableSamples.map((s) => s.subsystem))],
    [applicableSamples],
  )
  const effectiveSampleFilter =
    sampleFilter === 'all' || sampleSubsystems.includes(sampleFilter) ? sampleFilter : 'all'
  const visibleSamples = useMemo(
    () => (effectiveSampleFilter === 'all'
      ? applicableSamples
      : applicableSamples.filter((s) => s.subsystem === effectiveSampleFilter)),
    [applicableSamples, effectiveSampleFilter],
  )

  const lineCount = useMemo(() => input.split('\n').filter((l) => l.trim()).length, [input])

  const run = (text = input, n = limit, fresh = true, ver = vaultVersion) => {
    setResults(analyze(text, { limit: n, vaultVersion: ver }))
    if (fresh || text !== analyzedText.current) setRunId((id) => id + 1)
    analyzedText.current = text
  }

  const loadSample = (sample) => {
    setInput(sample.text)
    run(sample.text)
  }

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <svg className="logo" viewBox="0 0 64 64" aria-hidden="true">
            <polygon points="32,4 60,58 4,58" fill="#ffd814" />
            <path d="M32 22c8 6 10 16 4 26" stroke="#1d1f27" strokeWidth="5" fill="none" strokeLinecap="round" />
          </svg>
          <div>
            <h1>Vault Ponytail</h1>
            <p className="tagline">Paste Vault log errors. Find out whether to look inside Vault or outside it.</p>
          </div>
        </div>
        <div className="catalog-stats">
          {catalog.entries.length} known errors &middot; {subsystems.size} subsystems
        </div>
      </header>

      <main className="main">
        <section className="input-panel">
          <label htmlFor="log-input" className="panel-title">Vault log output</label>
          <textarea
            id="log-input"
            className="log-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) run()
            }}
            placeholder={'2024-05-01T10:00:00.000Z [ERROR] core: failed to unseal: error="..."\n\nPaste one or many lines from the Vault server log, journalctl, or CLI/API error output.'}
            spellCheck={false}
          />
          <div className="input-actions">
            <button className="analyze-btn" onClick={() => run()} disabled={!input.trim()}>
              Analyze
            </button>
            <label className="limit">
              Vault
              <select value={vaultVersion || ''} onChange={(e) => { const ver = e.target.value; setVaultVersion(ver); if (results) run(input, limit, false, ver) }}>
                {VAULT_VERSIONS.map((v) => <option key={v} value={v}>{v}.x</option>)}
              </select>
            </label>
            <label className="limit">
              Show top
              <select value={limit} onChange={(e) => { const n = Number(e.target.value); setLimit(n); if (results) run(input, n, false) }}>
                {[3, 5, 10].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </label>
            <button className="clear-btn" onClick={() => { setInput(''); setResults(null) }} disabled={!input}>
              Clear
            </button>
            <span className="hint">{lineCount} line{lineCount === 1 ? '' : 's'} &middot; Ctrl/Cmd+Enter</span>
          </div>
          <div className="samples">
            <div className="samples-header">
              <span>Try a sample ({visibleSamples.length}):</span>
              <select
                className="sample-filter"
                aria-label="Filter samples by subsystem"
                value={effectiveSampleFilter}
                onChange={(e) => setSampleFilter(e.target.value)}
              >
                <option value="all">All subsystems ({applicableSamples.length})</option>
                {sampleSubsystems.map((sub) => (
                  <option key={sub} value={sub}>{sub}</option>
                ))}
              </select>
            </div>
            <div className="sample-list">
              {visibleSamples.map((s) => (
                <button key={s.id} className="sample-btn" onClick={() => loadSample(s)}>
                  <span className={`sample-sub subsystem-${s.subsystem}`}>{s.subsystem}</span>
                  {s.title}
                </button>
              ))}
            </div>
          </div>
        </section>

        <section className="results-panel" aria-live="polite">
          {results === null && (
            <div className="placeholder">
              <h2>Where should I look?</h2>
              <p>
                Each match tells you whether the cause is most likely <span className="loc loc-internal">Internal</span> to
                Vault, <span className="loc loc-external">External</span> (storage backend, KMS/HSM, network, IAM), or{' '}
                <span className="loc loc-both">Both</span>, followed by an ordered checklist.
              </p>
            </div>
          )}
          {results && results.length === 0 && <NoMatch />}
          {results && results.length > 0 && (
            <>
              <h2 className="panel-title">{results.length} ranked match{results.length === 1 ? '' : 'es'}</h2>
              {results.map((r, i) => (
                <ResultCard key={`${runId}-${r.entry.id}`} result={r} rank={i + 1} defaultOpen={i === 0} />
              ))}
            </>
          )}
        </section>
      </main>

      <footer className="footer">
        Catalog seeded from error strings in{' '}
        <a href="https://github.com/hashicorp/vault" target="_blank" rel="noreferrer">hashicorp/vault</a> and related
        HashiCorp libraries. Runs entirely in your browser; nothing you paste leaves the page.
      </footer>
    </div>
  )
}

export default App
