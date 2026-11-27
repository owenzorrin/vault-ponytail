import { tokenize } from './matcher.js'
import articleData from './data/vault-articles.json'

const articles = articleData.articles.map((a) => ({
  ...a,
  tokens: a.keywords.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 2),
}))

// Rank documentation pages for a catalog entry against the pasted log.
// Query terms come from the entry (id/title/subsystem weighted highest) and
// the matched log lines; score is the weighted count of keyword occurrences,
// with a bonus for pages in a section matching the entry's subsystem.
export function rankArticles(entry, matchedText = '', { limit = 4 } = {}) {
  const STOP = new Set(['vault'])  // 'vault' appears in every Vault doc page
  const entryTokens = new Set(tokenize(`${entry.id.replace(/-/g, ' ')} ${entry.title} ${entry.subsystem}`).filter((t) => !STOP.has(t)))
  const inputTokens = new Set(tokenize(matchedText))
  const scored = []
  for (const a of articles) {
    let score = 0
    for (const t of a.tokens) {
      if (entryTokens.has(t)) score += 2
      else if (inputTokens.has(t)) score += 1
    }
    if (score < 4) continue
    if (a.section.includes(entry.subsystem) || a.title.toLowerCase().includes(entry.subsystem)) score += 6
    if (a.url.includes('/api-docs/')) score *= 0.65  // conceptual guides answer 'how to troubleshoot' better than raw API refs
    // A long keyword list should not win on volume alone.
    score = score / Math.sqrt(a.tokens.length / 20 + 1)
    scored.push({ article: { title: a.title, url: a.url, section: a.section }, score })
  }
  return scored.sort((x, y) => y.score - x.score).slice(0, limit)
}
