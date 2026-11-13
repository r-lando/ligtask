# TALGED UI audit — Impeccable

Date: 2026-10-16. Review only; no UI changes made.

## Implementation integrity verdict

Needs correction before a broader user trial. The navigation, branding and
severity order are coherent, but accessibility and responsive implementation
lag behind the desktop presentation. Preserve the supplied logo, purple identity,
dashboard functions and Critical-to-Info order; no visual redesign is required.

## Evidence and limits

Inspected the live authenticated History and Chronolog Results screens in the
in-app browser at a 1327 x 824 desktop viewport, plus repository/upload source,
shared styles, navigation and result controls. Contrast calculations use source
colors, not sampled antialiased screenshot pixels. The Impeccable engine could
not initialize because its cache write/download was unavailable in the sandbox;
the bundled detector did not run. No PRODUCT.md or DESIGN.md was found.

No physical-device, synthesized-touch, screen-reader, narrow-viewport, text-zoom,
network-throttling or full keyboard walkthrough was performed. Source evidence
is distinguished below from rendered observations. Scores are reviewer estimates,
not WCAG certification, performance benchmarks or deterministic detector output.

## Audit health

| Dimension | Score / 4 | Reason |
| --- | --- | --- |
| Accessibility | 1 | Keyboard-inaccessible upload target, unlabeled repository input and low contrast |
| Performance | 3 | Small existing production bundle; external font loading remains; no timing benchmark |
| Theming | 2 | Tokens exist, but many inline colors bypass them |
| Responsive design | 1 | Desktop layout visible; fixed sidebar and grids lack narrow-layout rules |
| Implementation integrity | 2 | Clear product structure; controls and coverage presentation have inconsistent semantics |
| Total | 9 / 20 | Poor technical readiness under this rubric; not a request for aesthetic replacement |

## Findings

### P1 — ZIP upload is not keyboard operable

Location: frontend/src/App.tsx:612-633. The file input is display:none and the
visible upload div has onClick but no keyboard focus, role or key handler.
Keyboard users cannot activate this upload path. WCAG 2.1.1 (Keyboard).
Use a labeled native file control or a real button with an accessible name.
Suggested command: `$impeccable harden`.

### P1 — Repository field lacks a programmatic label

Location: frontend/src/App.tsx:533. The GitHub URL field relies on a placeholder
and preceding visual text; no associated label or aria-label exists. Its inline
outline:none can also override the global focus outline. Add a visible associated
label and a reliably visible focus state. WCAG 1.3.1, 3.3.2, 2.4.7.
Suggested command: `$impeccable harden`.

### P1 — Muted text falls below normal-text contrast requirements

Locations: frontend/src/pages/HistoryScreen.tsx:197; frontend/src/App.tsx:166,195;
frontend/src/pages/AssessmentResultsScreen.tsx:1717. Source color #64748b against
#13101e is about 3.94:1; against #0c0a14 it is 4.13:1. #334155 against #0c0a14
is 1.90:1. These values fail the 4.5:1 normal-text threshold. The live history
dates, descriptions and results metadata are visibly subdued. WCAG 1.4.3.
Use accessible secondary-text tokens rather than replacing severity colors.
Suggested command: `$impeccable colorize`.

### P1 — Narrow layouts have no responsive adaptation

Locations: frontend/src/components/Sidebar.tsx:147 (224px fixed sidebar),
frontend/src/pages/HistoryScreen.tsx:169 (48px side padding),
frontend/src/pages/AssessmentResultsScreen.tsx:960 (six fixed grid columns),
frontend/src/App.tsx:1785 (horizontal overflow hidden). Source-derived risk:
at a 390px width, sidebar plus 96px padding leaves only 70px for content.
There are no viewport media queries in shared CSS. Clipping is not a solution.
Implement compact navigation and responsive grid columns without removing cards.
WCAG 1.4.10 is the relevant reflow target; narrow rendering still needs testing.
Suggested command: `$impeccable adapt`.

### P2 — Selected states are visual-only

Locations: frontend/src/components/Sidebar.tsx:173-188;
frontend/src/pages/AssessmentResultsScreen.tsx:984. Active navigation and selected
severity filters use color/borders but expose no current/pressed state.
Add aria-current to navigation and aria-pressed to toggle filters. WCAG 4.1.2.
Suggested command: `$impeccable harden`.

### P2 — Important data is too small and tokens are bypassed

Locations: frontend/src/pages/AssessmentResultsScreen.tsx:723,736,751,1059;
frontend/src/index.css:99. Multiple status/metadata labels are 9px; brand caption
is 7px. The live results screen is dense even at desktop size. Tiny type is not
by itself a WCAG failure, but increases reading effort. Inline #64748b/#334155
also prevent theme-level contrast corrections from propagating consistently.
Use a shared readable type scale and semantic color tokens, preserving hierarchy.
Suggested commands: `$impeccable typeset`, `$impeccable extract`.

### P2 — No-coverage state still has a green Completed badge

Location: frontend/src/pages/AssessmentResultsScreen.tsx:682-756. On the live
Chronolog results, dependency checking says Completed and 0 findings, while a
small note says no libraries were checked. The note is correct, but the strongest
visual signal suggests a passed check. Distinguish completion of the process from
coverage: display Not checked / No supported lockfile alongside the existing note.
No security conclusion should be inferred from this state.
Suggested command: `$impeccable clarify`.

### P2 — Reduced-motion handling is a global animation kill

Location: frontend/src/index.css:106. The 0.01ms override applies to every
animation/transition. Preserve persistent loading/progress status through static
alternatives and disable decorative movement selectively. This is a resilience
concern, not a verified WCAG violation in the current rendered state.
Suggested command: `$impeccable animate`.

## Totals and positives

0 P0, 4 P1, 4 P2, 0 P3 findings. Keep: native buttons for result/history actions,
text severity labels rather than color alone, alert roles for report errors,
global keyboard focus styling, transparent supplied logo, explicit dependency
coverage notes and file-context totals. No runtime performance failure was observed.

## Recommended sequence

1. `$impeccable harden` — upload keyboard behavior, input labels/focus and states.
2. `$impeccable colorize` then `$impeccable typeset` — contrast and readable metadata.
3. `$impeccable adapt` — narrow layout, zoom, 44px touch-target review and device tests.
4. `$impeccable clarify` — dependency no-coverage wording and status hierarchy.
5. `$impeccable extract` — replace repeated inline styles with shared tokens.
6. `$impeccable animate` — intentional reduced-motion alternatives.
7. `$impeccable polish` — final consistency pass, then rerun the audit.

Do not treat ordinary purple branding or Inter as defects by themselves: both
are incumbent choices and the user explicitly requested their preservation.
