import { useState } from 'react'

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <button className="copy-btn" onClick={copy} title="Copy command">
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

function Checklist({ steps }) {
  const [done, setDone] = useState(() => steps.map(() => false))
  const toggle = (i) => setDone((d) => d.map((v, j) => (j === i ? !v : v)))
  const count = done.filter(Boolean).length

  return (
    <div className="checklist">
      <div className="checklist-progress">{count}/{steps.length} checked</div>
      <ol>
        {steps.map((s, i) => (
          <li key={i} className={done[i] ? 'done' : ''}>
            <label>
              <input type="checkbox" checked={done[i]} onChange={() => toggle(i)} />
              <span>{s.step}</span>
            </label>
            {s.command && (
              <div className="command">
                <code>{s.command}</code>
                <CopyButton text={s.command} />
              </div>
            )}
          </li>
        ))}
      </ol>
    </div>
  )
}

export default Checklist
