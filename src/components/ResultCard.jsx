import { useMemo, useState } from 'react'
import Checklist from './Checklist.jsx'
import { rankArticles } from '../articles.js'

const LOCATION_LABEL = { internal: 'Internal', external: 'External', both: 'Both' }
const LOCATION_HINT = {
  internal: 'Most likely a Vault configuration, state or usage problem.',
  external: 'Most likely outside Vault: storage, KMS/HSM, network, IAM or the client.',
  both: 'Could be Vault itself or a dependency; check both columns.',
}

function ResultCard({ result, rank, defaultOpen }) {
  const { entry, confidence, matchedLines } = result
  const [open, setOpen] = useState(defaultOpen)
  const articles = useMemo(
    () => rankArticles(entry, matchedLines.join('\n')),
    [entry, matchedLines],
  )

  return (
    <article className={`result-card loc-border-${entry.location}`}>
      <header className="card-header">
        <span className="rank">#{rank}</span>
        <span className={`badge subsystem-${entry.subsystem}`}>{entry.subsystem}</span>
        <span className={`loc loc-${entry.location}`} title={LOCATION_HINT[entry.location]}>
          {LOCATION_LABEL[entry.location]}
        </span>
        {entry.versions && (
          <span className="badge version" title="This error only exists in these Vault versions">
            v{entry.versions.since ? `≥${entry.versions.since}` : ''}{entry.versions.until ? `–${entry.versions.until}` : ''}
          </span>
        )}
        <h3>{entry.title}</h3>
        <span className="confidence" title="Match confidence">
          <span className="confidence-bar"><span style={{ width: `${confidence}%` }} /></span>
          {confidence}%
        </span>
      </header>

      <p className="summary">{entry.summary}</p>

      {matchedLines.length === 0 && (
        <div className="matched">
          <span className="label">Partial match:</span>
          <span className="muted">no exact pattern matched; most words of a known error appear in the input.</span>
        </div>
      )}
      {matchedLines.length > 0 && (
        <div className="matched">
          <span className="label">Matched:</span>
          <code>{matchedLines[0].length > 220 ? `${matchedLines[0].slice(0, 220)}...` : matchedLines[0]}</code>
        </div>
      )}

      <div className="causes">
        <div className="cause-col">
          <h4>Inside Vault</h4>
          {entry.internal_causes.length ? (
            <ul>{entry.internal_causes.map((c, i) => <li key={i}>{c}</li>)}</ul>
          ) : (
            <p className="muted">No common Vault-internal cause.</p>
          )}
        </div>
        <div className="cause-col">
          <h4>Outside Vault</h4>
          {entry.external_causes.length ? (
            <ul>{entry.external_causes.map((c, i) => <li key={i}>{c}</li>)}</ul>
          ) : (
            <p className="muted">No common external cause.</p>
          )}
        </div>
      </div>

      <button className="toggle" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        {open ? '▾' : '▸'} Troubleshooting checklist ({entry.troubleshooting_steps.length} steps)
      </button>
      <div hidden={!open}>
        <Checklist steps={entry.troubleshooting_steps} />
      </div>

      {articles.length > 0 && (
        <div className="articles">
          <h4>Related KB &amp; docs</h4>
          <ol>
            {articles.map(({ article }) => (
              <li key={article.url}>
                <span className={`article-tag article-tag-${article.source}`}>
                  {article.source === 'kb' ? 'KB' : 'Docs'}
                </span>
                <a href={article.url} target="_blank" rel="noreferrer">{article.title}</a>
                {article.source !== 'kb' && (
                  <span className="muted article-section">{article.section}</span>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="references">
        {entry.references.map((r) => (
          <a key={r.url} href={r.url} target="_blank" rel="noreferrer">{r.title}</a>
        ))}
      </div>
    </article>
  )
}

export default ResultCard
