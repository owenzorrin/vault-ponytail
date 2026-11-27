import { tokenize } from './matcher.js'
import docData from './data/vault-articles.json'
import kbData from './data/vault-kb-articles.json'

const toIndexed = (list, defaultSource) =>
  list.map((a) => ({
    ...a,
    source: a.source || defaultSource,
    titleTokens: new Set(tokenize(a.title)),
    tokens: new Set(tokenize(a.keywords)),
  }))

const articles = [
  ...toIndexed(kbData.articles, 'kb'),
  ...toIndexed(docData.articles, 'docs'),
]

// Document frequency & IDF so specific terms (approle, mlock, quorum) outweigh
// generic Vault words (auth, login, role, cluster). Also doubles as a vocabulary
// set so random lease IDs, UUIDs, and IPs in large log pastes are skipped in O(1).
const docFreq = new Map()
for (const a of articles) {
  const all = new Set([...a.titleTokens, ...a.tokens])
  for (const t of all) docFreq.set(t, (docFreq.get(t) || 0) + 1)
}
const idf = (t) => Math.log((articles.length + 1) / ((docFreq.get(t) || 0) + 1))

// Rank Vault KB articles and official documentation pages for a catalog entry
// against the pasted log. Distinct IDF-weighted token matches in the title weigh
// more than body/keyword matches, so specific error terms outweigh generic words.
export function rankArticles(entry, matchedText = '', { limit = 5 } = {}) {
  const STOP = new Set([
    'vault', 'error', 'errors', 'failed', 'unable', 'using', 'when', 'with', 'from', 'that', 'this',
    'making', 'api', 'request', 'code', 'url', 'http', 'https', 'get', 'put', 'post', 'delete',
  ])
  const entryTokens = [...new Set(
    tokenize(`${entry.id.replace(/-/g, ' ')} ${entry.title}`)
      .filter((t) => !STOP.has(t) && docFreq.has(t)),
  )]
  const entrySet = new Set(entryTokens)
  const inputTokens = [...new Set(
    tokenize(matchedText)
      .filter((t) => !STOP.has(t) && !entrySet.has(t) && docFreq.has(t)),
  )].slice(0, 60)

  const scored = []
  for (const a of articles) {
    let score = 0
    for (const t of entryTokens) {
      const w = idf(t)
      if (a.titleTokens.has(t)) score += 3 * w
      else if (a.tokens.has(t)) score += 1.5 * w
    }
    for (const t of inputTokens) {
      const w = idf(t)
      if (a.titleTokens.has(t)) score += 1.5 * w
      else if (a.tokens.has(t)) score += 0.75 * w
    }
    if (score < 4) continue
    if (a.section.toLowerCase().includes(entry.subsystem) || a.titleTokens.has(entry.subsystem)) score += 2
    if (a.source === 'kb') score *= 1.15  // dedicated troubleshooting KB articles directly address errors
    if (a.url.includes('/api-docs/')) score *= 0.65  // conceptual guides answer 'how to troubleshoot' better than raw API refs
    scored.push({ article: { title: a.title, url: a.url, section: a.section, source: a.source }, score })
  }
  return scored.sort((x, y) => y.score - x.score).slice(0, limit)
}
