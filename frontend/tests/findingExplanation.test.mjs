import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { stripTypeScriptTypes } from 'node:module'

const source = await readFile(new URL('../src/services/findingExplanation.ts', import.meta.url), 'utf8')
const compiled = stripTypeScriptTypes(source)
const { severityContext, findingReview } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)

test('severity totals keep every context and severity separate', () => {
  const findings = [
    { severity: 'CRITICAL', file_context: 'Test / fixture' },
    { severity: 'CRITICAL', file_context: 'Scanner rule' },
    { severity: 'INFO', file_context: 'Application / other' },
    { severity: 'CRITICAL' },
  ]
  assert.equal(severityContext(findings, 'CRITICAL'), '0 app/other files · 1 test files · 1 scanner rules · 1 unknown')
  assert.equal(severityContext(findings, 'INFO'), '1 app/other files · 0 test files · 0 scanner rules')
})

test('review text explains advisory limits and does not dismiss fixture credentials', () => {
  assert.match(findingReview({ category: 'DEPENDENCY' }), /reported security issue/)
  const secret = findingReview({ category: 'SECRET', file_context: 'Test / fixture' })
  assert.match(secret, /has not checked whether it works/)
  assert.match(secret, /even in tests/)
  assert.match(secret, /not proof that someone can attack/)
  assert.match(findingReview({ category: 'SAST', file_context: 'Scanner rule' }), /example used to teach the scanner/)
})
