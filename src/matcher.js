import defaultCatalog from './data/vault-errors.json'

const ANSI_RE = /\x1b\[[0-9;?]*[ -\/]*[@-~]/g
const PREFIX_RES = [
  // syslog / journald: "Nov 26 16:52:01 host vault[1234]: "
  /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+?(\[\d+\])?:\s*/,
  // ISO-8601 / RFC3339 timestamps, optionally bracketed
  /^\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\]?\s*/,
  // Go log package: "2024/01/02 15:04:05 "
  /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*/,
  // hclog level: "[ERROR] ", "[WARN]  ", "ERROR: "
  // Bracketed or colon-terminated levels in any case; bare levels only in upper
  // case so CLI messages such as "Error initializing listener" keep their first word.
  /^\[(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|ERR|FATAL|PANIC|CRIT)\]:?\s*/i,
  /^(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|ERR|FATAL|PANIC|CRIT):\s+/i,
  /^(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|ERR|FATAL|PANIC|CRIT)\s+/,
  // logfmt / JSON-ish level and timestamp keys, in either order
  /^(?:@?level|lvl)=["']?\w+["']?\s+/i,
  /^(?:@?timestamp|time|ts)=["']?[0-9T:.\-+Z]+["']?\s+/i,
]
const KV_TIMESTAMP_RE = /\b(?:@?timestamp|time|ts)=["']?[0-9T:.\-+Z]+["']?\s*/gi

const STOPWORDS = new Set([
  'the', 'and', 'for', 'from', 'with', 'not', 'was', 'are', 'has', 'have', 'this',
  'that', 'error', 'err', 'failed', 'failure', 'vault', 'into', 'when', 'while',
])

export const GENERIC_TRIAGE = [
  { step: 'Check seal state, HA mode and storage type of the node', command: 'vault status' },
  { step: 'Check node health from the load balancer point of view', command: 'curl -s $VAULT_ADDR/v1/sys/health | jq' },
  { step: 'Reproduce with debug logging to capture the full error chain', command: 'vault monitor -log-level=debug' },
  { step: 'Or restart the server with debug logging enabled', command: 'vault server -config=/etc/vault.d -log-level=debug' },
  { step: 'Check the audit log for the failing request (path, client token accessor, error)', command: 'vault audit list -detailed' },
  { step: 'Check storage backend health (raft peers / Consul / cloud backend status)', command: 'vault operator raft list-peers' },
  { step: 'Run the built-in diagnostics against the server config', command: 'vault operator diagnose -config=/etc/vault.d/vault.hcl' },
]

export function stripAnsi(text) {
  return text.replace(ANSI_RE, '')
}

export function normalizeLine(line) {
  let out = stripAnsi(line).trim()
  let changed = true
  while (changed) {
    changed = false
    for (const re of PREFIX_RES) {
      const next = out.replace(re, '')
      if (next !== out) {
        out = next
        changed = true
      }
    }
  }
  return out.replace(KV_TIMESTAMP_RE, '').replace(/\s+/g, ' ').trim()
}

export function normalize(text) {
  return String(text ?? '')
    .split(/\r?\n/)
    .map(normalizeLine)
    .filter(Boolean)
}

export function tokenize(text) {
  return (text.toLowerCase().match(/[a-z0-9_]+/g) || []).filter(
    (t) => t.length >= 3 && !STOPWORDS.has(t),
  )
}

// Turn a regex source into the literal words it would match, for fuzzy overlap.
function patternTokens(pattern) {
  const literal = pattern
    .replace(/\(\?<?[!=](?:[^()]|\([^()]*\))*\)/g, ' ')
    .replace(/\([^()]*\)\?/g, ' ')
    .replace(/\\[bBdDsSwW]/g, ' ')
    .replace(/\\(.)/g, '$1')
    .replace(/\[[^\]]*\]/g, ' ')
    .replace(/\{\d+(,\d*)?\}/g, ' ')
  return [...new Set(tokenize(literal))]
}

// hclog logger names (e.g. "storage.raft: ...") hint at the subsystem that emitted the line.
const LOGGER_SUBSYSTEMS = [
  [/^storage\.raft|^raft/, 'raft'],
  [/^storage/, 'storage'],
  [/^expiration|^token/, 'token'],
  [/^replication/, 'replication'],
  [/^audit/, 'audit'],
  [/^identity/, 'identity'],
  [/^secrets\.pki|^pki/, 'pki'],
  [/^secrets\.transit|^transit/, 'transit'],
  [/^auth\./, 'auth'],
  [/^core\.cluster-listener|^core\.request-forward|^ha/, 'ha'],
  [/^seal|^core\.seal/, 'seal'],
]

export function loggerSubsystem(line) {
  const m = /^([a-z][\w-]*(?:\.[\w-]+)*):\s/i.exec(line)
  if (!m) return null
  const hit = LOGGER_SUBSYSTEMS.find(([re]) => re.test(m[1].toLowerCase()))
  return hit ? hit[1] : null
}

// CLI/API errors span several lines ("Code: 403. Errors:" / "* permission denied"),
// so patterns are also tried against short windows of consecutive lines.
const WINDOW = 6

function windows(lines) {
  const out = []
  for (let i = 0; i < lines.length - 1; i++) {
    out.push(lines.slice(i, i + WINDOW).join(' '))
  }
  return out
}

const compiledCache = new WeakMap()

function compile(catalog) {
  if (compiledCache.has(catalog)) return compiledCache.get(catalog)
  const compiled = catalog.entries.map((entry) => ({
    entry,
    patterns: entry.patterns.map((source) => ({
      source,
      re: new RegExp(source, 'i'),
      tokens: patternTokens(source),
      specificity: Math.min(patternTokens(source).length, 6) / 6,
    })),
  }))
  compiledCache.set(catalog, compiled)
  return compiled
}

function scoreEntry(compiledEntry, lines, blocks, inputTokens) {
  const hitPatterns = new Set()
  const specificity = new Map(compiledEntry.patterns.map((p) => [p.source, p.specificity]))
  const matchedLines = new Set()
  let longestMatch = 0
  let loggerAffinity = false
  let deepestPosition = 0
  let bestOverlap = 0
  let bestOverlapTokens = 0

  for (const p of compiledEntry.patterns) {
    for (const line of lines) {
      const m = p.re.exec(line)
      if (m) {
        hitPatterns.add(p.source)
        matchedLines.add(line)
        longestMatch = Math.max(longestMatch, m[0].length)
        // Go error chains put the root cause last: prefer matches further right.
        deepestPosition = Math.max(deepestPosition, m.index / Math.max(line.length, 1))
        if (loggerSubsystem(line) === compiledEntry.entry.subsystem) loggerAffinity = true
      }
    }
    if (!hitPatterns.has(p.source)) {
      for (const block of blocks) {
        const m = p.re.exec(block)
        if (m) {
          hitPatterns.add(p.source)
          matchedLines.add(block)
          longestMatch = Math.max(longestMatch, m[0].length)
          break
        }
      }
    }
    if (p.tokens.length >= 2) {
      const shared = p.tokens.filter((t) => inputTokens.has(t)).length
      const overlap = shared / p.tokens.length
      if (overlap > bestOverlap || (overlap === bestOverlap && p.tokens.length > bestOverlapTokens)) {
        bestOverlap = overlap
        bestOverlapTokens = p.tokens.length
      }
    }
  }

  let score = 0
  if (hitPatterns.size > 0) {
    // Specific (many-literal-word) patterns outrank generic ones like "permission denied".
    const specs = [...hitPatterns].map((src) => specificity.get(src)).sort((a, b) => b - a)
    const extra = specs.slice(1, 3).reduce((sum, s) => sum + s, 0)
    score =
      0.5 +
      0.25 * specs[0] +
      0.05 * extra +
      0.1 * bestOverlap +
      0.02 * deepestPosition +
      (loggerAffinity ? 0.06 : 0) +
      Math.min(longestMatch / 2000, 0.03)
  } else if (bestOverlapTokens >= 4 && bestOverlap >= 0.75) {
    // No regex hit: only a long pattern that shares most of its words counts.
    score = 0.5 * bestOverlap
  }

  return {
    score: Math.min(score, 1),
    regexHits: hitPatterns.size,
    overlap: bestOverlap,
    matchedPatterns: [...hitPatterns],
    matchedLines: [...matchedLines],
  }
}

/**
 * Analyze pasted Vault log text against the error catalog.
 * Returns matches sorted by confidence (0-100), highest first.
 */
// Minor-granularity compare, e.g. cmpVersion("1.15", "2.0") < 0
export function cmpVersion(a, b) {
  const pa = a.split('.').map(Number)
  const pb = b.split('.').map(Number)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0)
    if (d) return d
  }
  return 0
}

// True when an entry's version range covers the given Vault minor version.
// Entries without a `versions` field apply to every supported version.
export function appliesTo(entry, vaultVersion) {
  if (!vaultVersion || !entry.versions) return true
  const { since, until } = entry.versions
  if (since && cmpVersion(vaultVersion, since) < 0) return false
  if (until && cmpVersion(vaultVersion, until) > 0) return false
  return true
}

export const VAULT_VERSIONS = defaultCatalog.vault_versions || []

export function analyze(text, { catalog = defaultCatalog, limit = 5, minScore = 0.3, vaultVersion = null } = {}) {
  const lines = normalize(text)
  if (lines.length === 0) return []
  const inputTokens = new Set(tokenize(lines.join(' ')))
  const blocks = windows(lines)

  return compile(catalog)
    .filter((c) => appliesTo(c.entry, vaultVersion))
    .map((c) => ({ entry: c.entry, ...scoreEntry(c, lines, blocks, inputTokens) }))
    .filter((r) => r.score >= minScore)
    .sort((a, b) => b.score - a.score || b.regexHits - a.regexHits)
    .slice(0, limit)
    .map((r) => ({ ...r, confidence: Math.round(r.score * 100) }))
}

export const catalog = defaultCatalog
