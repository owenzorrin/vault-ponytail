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

// Rank Vault KB articles and official documentation pages for a catalog entry
// against the pasted log. Distinct token matches in the title weigh more than
// body/keyword matches, so a single repeated generic word (like "seal") cannot
// swamp a specific error term (like "mlock" or "quorum").
export function rankArticles(entry, matchedText = '', { limit = 5 } = {}) {
  const STOP = new Set([
    'vault', 'error', 'errors', 'failed', 'unable', 'using', 'when', 'with', 'from', 'that', 'this',
    'making', 'api', 'request', 'code', 'url', 'http', 'https', 'get', 'put', 'post', 'delete',
  ])
  const entryTokens = new Set(tokenize(`${entry.id.replace(/-/g, ' ')} ${entry.title}`).filter((t) => !STOP.has(t)))
  const inputTokens = new Set(tokenize(matchedText).filter((t) => !STOP.has(t)))
  const scored = []
  for (const a of articles) {
    let score = 0
    for (const t of entryTokens) {
      if (a.titleTokens.has(t)) score += 4
      else if (a.tokens.has(t)) score += 2
    }
    for (const t of inputTokens) {
      if (entryTokens.has(t)) continue
      if (a.titleTokens.has(t)) score += 2
      else if (a.tokens.has(t)) score += 1
    }
    if (score < 4) continue
    if (a.section.toLowerCase().includes(entry.subsystem) || a.titleTokens.has(entry.subsystem)) score += 2
    if (a.source === 'kb') score *= 1.15  // dedicated troubleshooting KB articles directly address errors
    if (a.url.includes('/api-docs/')) score *= 0.65  // conceptual guides answer 'how to troubleshoot' better than raw API refs
    scored.push({ article: { title: a.title, url: a.url, section: a.section, source: a.source }, score })
  }
  return scored.sort((x, y) => y.score - x.score).slice(0, limit)
}
