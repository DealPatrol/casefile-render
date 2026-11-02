# SignalShield

SignalShield is a local-first scam and impersonation message analyzer. It runs as a dependency-free static web app and does not upload pasted content.

## Features

- Transparent checks for urgency, payment traps, credential requests, impersonation, secrecy, remote access, and suspicious URLs
- Actionable safety guidance and a safe verification note
- Local JSON report export
- Optional browser-provided on-device `LanguageModel` explanation when available
- No account, paid API, analytics, backend, or external dependency

## Run locally

Open `index.html`, or serve the folder with any static server:

```sh
python3 -m http.server 4173
```

## Privacy and limitations

Analysis happens in the browser. SignalShield is a second opinion, not a guarantee, and should not replace independent verification through official channels.
