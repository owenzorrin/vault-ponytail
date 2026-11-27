import { useMemo, useState } from 'react'
import { analyze, catalog } from './matcher.js'
import ResultCard from './components/ResultCard.jsx'
import NoMatch from './components/NoMatch.jsx'

const SAMPLES = [
  'seal-awskms',
  'raft-heartbeat-election',
  'token-permission-denied',
  'tls-unknown-authority',
  'storage-dynamodb',
]
  .map((id) => catalog.entries.find((e) => e.id === id))
  .filter(Boolean)

const subsystems = new Set(catalog.entries.map((e) => e.subsystem))

function App() {
  const [input, setInput] = useState('')
  const [results, setResults] = useState(null)
  const [limit, setLimit] = useState(5)
  const [runId, setRunId] = useState(0)

  const lineCount = useMemo(() => input.split('\n').filter((l) => l.trim()).length, [input])

  const run = (text = input, n = limit, fresh = true) => {
    setResults(analyze(text, { limit: n }))
    if (fresh) setRunId((id) => id + 1)
  }

  const loadSample = (entry) => {
    setInput(entry.examples[0])
    run(entry.examples[0])
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
            <span>Try a sample:</span>
            {SAMPLES.map((e) => (
              <button key={e.id} className="sample-btn" onClick={() => loadSample(e)}>{e.title}</button>
            ))}
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
