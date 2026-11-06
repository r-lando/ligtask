# Release blockers

- [ ] Restore a positive `ASSESSMENTS_PER_DAY` before hosting, sharing with users, or declaring MVP testing finished. Local testing temporarily uses `0` (unlimited daily assessments). Suggested starting value: 5; choose the final quota with the owner. Verify per-user isolation, quota exhaustion, and rolling 24-hour reset before release. Do not disable concurrency, queue, upload, or extraction limits.

This checklist is a durable reminder, not a scheduled notification.

Owner instruction: keep the local daily quota disabled until the owner explicitly says TALGED is going to be hosted. Raise this checklist item at that milestone; do not restore it early or choose a reminder date on the owner's behalf.
