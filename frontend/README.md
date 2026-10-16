# TALGED frontend

React and TypeScript interface for GitHub/ZIP assessments, findings, history,
and HTML/PDF reports.

## Development

Run `npm ci` followed by `npm run dev` from this directory.

The API defaults to `http://127.0.0.1:8000`. Set `VITE_API_BASE_URL` in
`.env.local` to change it, then restart Vite. Vite variables are public build
configuration; never put credentials in them.

## Checks

Run `npm test`, `npm run build`, and `npm run lint`. The build includes type checking.
The API polling tests use Node.js 24's TypeScript stripping support.

See the [project README](../README.md) for backend setup and operating limits.
