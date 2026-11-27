import { GENERIC_TRIAGE } from '../matcher.js'
import Checklist from './Checklist.jsx'

function NoMatch() {
  return (
    <div className="result-card no-match">
      <h3>No known error matched</h3>
      <p className="summary">
        The pasted text did not match any catalog entry. Work through the generic triage below, then paste the first
        ERROR line that appears before the symptom; that line usually names the real cause.
      </p>
      <Checklist steps={GENERIC_TRIAGE} />
    </div>
  )
}

export default NoMatch
