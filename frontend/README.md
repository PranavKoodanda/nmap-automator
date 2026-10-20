# Nmap Automator Frontend

React and Vite frontend for the Nmap Automator security assessment tool. The
current implementation is a browser-only demonstration; it does not run Nmap
or call a backend.

## Run locally

```powershell
cd frontend
npm install
npm run dev
```

## Quality checks

```powershell
npm run lint
npm run build
```

The dashboard and feature pages run in explicit demo mode. No scan results are
from real network activity. Demo fixtures are isolated in
`src/services/mockData.js`, and `src/services/scanService.js` provides local
scan-history and simulated-scan functions. Demo PDF generation is isolated in
`src/services/pdfReport.js`. New demo history is saved in browser local storage.

Before backend integration, agree on endpoint names, request bodies, response
schemas, and error formats with the backend developer. Follow the shared
contract in `../docs/api-contract.md` when it becomes available; do not infer
an API from the demo service.