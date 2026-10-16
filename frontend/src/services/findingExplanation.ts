import type { AssessmentFinding, FindingSeverity } from '../types/assessment'

export function contextLabel(context: string) {
  return ({ 'Application / other': 'App and other files', 'Test / fixture': 'Test files', 'Scanner rule': 'Scanner rules' } as Record<string, string>)[context] ?? 'Unknown file group'
}

export function severityContext(findings: AssessmentFinding[], severity: FindingSeverity) {
  const matching = findings.filter(finding => finding.severity === severity)
  const application = matching.filter(finding => finding.file_context === 'Application / other').length
  const tests = matching.filter(finding => finding.file_context === 'Test / fixture').length
  const rules = matching.filter(finding => finding.file_context === 'Scanner rule').length
  const unknown = matching.length - application - tests - rules
  return `${application} app/other files · ${tests} test files · ${rules} scanner rules${unknown ? ` · ${unknown} unknown` : ''}`
}

export function findingReview(finding: AssessmentFinding) {
  const context = finding.file_context === 'Test / fixture'
    ? 'This looks like a test file. Check whether your live app uses it. Real passwords or access keys still need protection, even in tests.'
    : finding.file_context === 'Scanner rule'
      ? 'This looks like a scanner rule file. The finding may be in an example used to teach the scanner what to look for, rather than in your app.'
      : 'Check whether your app uses this file or software library, and whether user input could trigger the problem.'
  const category = finding.category === 'DEPENDENCY'
    ? 'A software library version in your project has a reported security issue. Check whether the issue affects how your app uses it, then update to a version that fixes it.'
    : finding.category === 'SECRET'
      ? 'TALGED found text that looks like a password or access key. It has not checked whether it works. Do not share the value. If it is real and exposed, replace or disable it and remove it from your code.'
      : finding.category === 'CONFIGURATION'
        ? 'TALGED found a setting that may be unsafe. Check whether your live app uses this setting, then follow the suggested fix if needed.'
        : 'TALGED found code that may cause a security problem. Check the nearby code and how it handles user input before deciding what to fix.'
  return `${category} ${context} This is a warning to review, not proof that someone can attack your app. Severity shows how serious the issue could be. File groups are based on file names and folders and may be wrong.`
}
