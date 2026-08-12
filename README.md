# HAW-KI Front-End Prototype

A minimal Flask-based front end that represents the intended LLM-assisted SOAR architecture.

## Included features

- Local LLM chat through an OpenAI-compatible endpoint
- Fixed security-analyst system prompt
- Operational metrics and alert-volume visualization
- Alert queue and incident summary
- Service-health checks for the LLM, Elasticsearch, and Kibana
- Safe links to Kibana and Elasticsearch
- Optional read-only Elasticsearch search
- No Elasticsearch credentials exposed to the browser
- Architecture overview dialog

## Directory structure

```text
soar_frontend/
├── app.py
├── .env.example
├── requirements.txt
├── README.md
├── templates/
│   └── index.html
└── static/
    ├── app.js
    └── style.css
```

## Run

```bash
cd soar_frontend
python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`, then start the server:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Elasticsearch mode

The default is `ENABLE_ES_SEARCH=false`. In that mode, the UI generates an investigation link but does not execute a search.

To enable direct search:

1. Create a read-only Elasticsearch API key.
2. Restrict it to the intended log indices.
3. Put the API key in `.env`.
4. Set `ENABLE_ES_SEARCH=true`.

The backend enforces a result limit and returns selected fields only. A dedicated policy gateway should replace this simple search endpoint before production use.

## Production notes

- Put the Flask service behind Nginx or Caddy.
- Add authentication before exposing it beyond a trusted lab network.
- Keep vLLM and Elasticsearch inaccessible from untrusted clients.
- Use HTTPS.
- Add CSRF protection, persistent sessions, RBAC, audit logging, and rate limiting.
- Treat all LLM-proposed queries and response actions as untrusted until validated.
