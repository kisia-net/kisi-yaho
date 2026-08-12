Yes. Containerize the Flask front end, its Python dependencies, configuration, and virtual environment in one image. Keep vLLM, Elasticsearch, and Kibana as separate services or external endpoints.

A virtual environment inside the image is technically redundant because the container already isolates Python packages, but using `/opt/venv` is valid and makes the Python runtime explicit. Python virtual environments do not need to be activated when their interpreter path is invoked directly or placed first in `PATH`. ([Python documentation][1])

## 1. Resulting directory structure

Add three files to the project:

```text
soar_frontend/
├── app.py
├── Dockerfile
├── compose.yaml
├── .dockerignore
├── .env
├── .env.example
├── requirements.txt
├── templates/
│   └── index.html
└── static/
    ├── app.js
    └── style.css
```

## 2. Update `requirements.txt`

Add Gunicorn so Flask is not run through its development server:

```text
Flask==3.1.1
python-dotenv==1.1.1
requests==2.32.4
gunicorn
```

## 3. Create `Dockerfile`

```dockerfile
# syntax=docker/dockerfile:1

FROM python:3.13-slim

# Prevent Python from creating .pyc files and ensure immediate log output.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Create an isolated Python environment inside the container.
RUN python -m venv "$VIRTUAL_ENV"

# Copy requirements separately to preserve Docker build caching.
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Create an unprivileged application user.
RUN groupadd --system soar \
    && useradd --system --gid soar --home-dir /app soar

COPY app.py .
COPY templates ./templates
COPY static ./static

RUN chown -R soar:soar /app

USER soar

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/config', timeout=3)"

CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
```

This image:

* Creates `/opt/venv`
* Places the virtual environment first in `PATH`
* Installs Flask and the other packages into that virtual environment
* Runs the service as an unprivileged user
* Uses Gunicorn rather than Flask’s development server
* Provides a Docker health check

Docker recommends explicit `WORKDIR` values and current official base images. It also recommends separating services by responsibility rather than placing the complete application stack in a single container. ([Docker Documentation][2])

## 4. Create `.dockerignore`

```dockerignore
# Python
__pycache__/
*.py[cod]
*.pyo
.pytest_cache/
.mypy_cache/

# Local virtual environments
.venv/
venv/
env/

# Secrets and local configuration
.env
.env.*
!.env.example

# Git and editor files
.git/
.gitignore
.vscode/
.idea/

# Operating-system files
.DS_Store
Thumbs.db

# Logs
*.log
```

The `.env` file must not be copied into the image because it may contain the LLM and Elasticsearch API keys. Docker specifically warns that, without `.dockerignore`, sensitive `.env` files and unrelated local files can enter the build context. ([Docker Documentation][3])

## 5. Create `compose.yaml`

For your current setup, where vLLM, Elasticsearch, and Kibana may be running on the Windows/WSL host:

```yaml
services:
  soar-frontend:
    build:
      context: .
      dockerfile: Dockerfile

    container_name: hawki-frontend

    restart: unless-stopped

    env_file:
      - .env

    ports:
      - "127.0.0.1:5000:5000"

    healthcheck:
      test:
        [
          "CMD",
          "python",
          "-c",
          "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/config', timeout=3)"
        ]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3

    networks:
      - hawki-network

networks:
  hawki-network:
    name: hawki-network
```

Using `env_file` passes variables from `.env` into the container. A project `.env` used only for Compose interpolation is not necessarily the same as explicitly attaching it to a service through `env_file`. ([Docker Documentation][4])

The binding:

```yaml
ports:
  - "127.0.0.1:5000:5000"
```

means that the web interface is accessible only from the workstation:

```text
http://127.0.0.1:5000
```

For LAN or OpenVPN access, change it later to:

```yaml
ports:
  - "5000:5000"
```

Do not do that until authentication and HTTPS are added.

## 6. Create `.env`

When the Flask application runs inside a container, `127.0.0.1` refers to the Flask container itself—not the Windows or WSL host.

For services running outside this Compose stack, use `host.docker.internal`:

```env
LLM_API_URL=http://host.docker.internal:8000/v1/chat/completions
LLM_MODEL=soar-local
LLM_API_KEY=replace-with-your-vllm-api-key

KIBANA_URL=http://host.docker.internal:5601
ELASTICSEARCH_URL=http://host.docker.internal:9200

ELASTICSEARCH_API_KEY=
ENABLE_ES_SEARCH=false
MAX_LOG_RESULTS=50

REQUEST_TIMEOUT=120
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false
```

Docker Desktop provides the special hostname `host.docker.internal` so a container can connect to a service listening on the host. ([Docker Documentation][5])

### Important host-binding issue

For the container to reach vLLM through:

```text
http://host.docker.internal:8000
```

vLLM must not listen exclusively on `127.0.0.1` inside WSL.

If vLLM is started directly, bind it to:

```bash
vllm serve openai/gpt-oss-20b \
    --host 0.0.0.0 \
    --port 8000 \
    --served-model-name soar-local \
    --api-key YOUR_API_KEY
```

Then control exposure through the Windows firewall and Docker networking.

If vLLM is already a Docker container in another Compose stack, the cleaner design is to attach both containers to the same Docker network rather than passing through the host.

## 7. Build the image

From the `soar_frontend` directory:

```bash
docker compose build
```

Or force a clean rebuild:

```bash
docker compose build --no-cache
```

Verify the image:

```bash
docker images
```

## 8. Start the container

```bash
docker compose up -d
```

Check its state:

```bash
docker compose ps
```

Expected output should resemble:

```text
NAME              STATUS
hawki-frontend    Up (...) (healthy)
```

Open:

```text
http://127.0.0.1:5000
```

## 9. Inspect logs

```bash
docker compose logs -f soar-frontend
```

Only recent lines:

```bash
docker compose logs --tail=100 soar-frontend
```

Inspect Gunicorn processes:

```bash
docker compose exec soar-frontend ps aux
```

## 10. Verify the virtual environment

Run:

```bash
docker compose exec soar-frontend which python
```

Expected:

```text
/opt/venv/bin/python
```

Check pip:

```bash
docker compose exec soar-frontend which pip
```

Expected:

```text
/opt/venv/bin/pip
```

Inspect installed packages:

```bash
docker compose exec soar-frontend pip list
```

Check the venv configuration:

```bash
docker compose exec soar-frontend cat /opt/venv/pyvenv.cfg
```

No activation command is needed because this Dockerfile sets:

```dockerfile
ENV PATH="/opt/venv/bin:$PATH"
```

Consequently, `python`, `pip`, and `gunicorn` resolve to the executables inside `/opt/venv`.

## 11. Test container connectivity

### LLM

```bash
docker compose exec soar-frontend python -c "
import os, requests
url = os.environ['LLM_API_URL'].rsplit('/chat/completions', 1)[0] + '/models'
headers = {'Authorization': 'Bearer ' + os.environ['LLM_API_KEY']}
response = requests.get(url, headers=headers, timeout=10)
print(response.status_code)
print(response.text[:500])
"
```

### Elasticsearch

Without authentication:

```bash
docker compose exec soar-frontend python -c "
import os, requests
response = requests.get(os.environ['ELASTICSEARCH_URL'], timeout=10)
print(response.status_code)
print(response.text[:500])
"
```

With an Elasticsearch API key:

```bash
docker compose exec soar-frontend python -c "
import os, requests
headers = {'Authorization': 'ApiKey ' + os.environ['ELASTICSEARCH_API_KEY']}
response = requests.get(
    os.environ['ELASTICSEARCH_URL'],
    headers=headers,
    timeout=10
)
print(response.status_code)
print(response.text[:500])
"
```

### Kibana

```bash
docker compose exec soar-frontend python -c "
import os, requests
response = requests.get(os.environ['KIBANA_URL'], timeout=10)
print(response.status_code)
"
```

## 12. Common connectivity failure

A common result is:

```text
Connection refused
```

The usual causes are:

1. The target service is not running.
2. The service listens only on `127.0.0.1`.
3. The wrong port is configured.
4. Windows Firewall blocks the connection.
5. The target is another container but its host port was not published.
6. The service requires HTTPS rather than HTTP.

Inside the Flask container, these addresses are generally wrong for host services:

```env
LLM_API_URL=http://127.0.0.1:8000/...
ELASTICSEARCH_URL=http://127.0.0.1:9200
KIBANA_URL=http://127.0.0.1:5601
```

They would instruct Flask to contact itself.

## 13. Development mode with live file updates

During development, mount the source code rather than rebuilding after every edit.

Create `compose.dev.yaml`:

```yaml
services:
  soar-frontend:
    volumes:
      - ./app.py:/app/app.py:ro
      - ./templates:/app/templates:ro
      - ./static:/app/static:ro

    environment:
      FLASK_DEBUG: "true"

    command:
      [
        "flask",
        "--app",
        "app.py",
        "run",
        "--host",
        "0.0.0.0",
        "--port",
        "5000",
        "--debug"
      ]
```

Run development mode:

```bash
docker compose -f compose.yaml -f compose.dev.yaml up --build
```

Use the normal configuration for persistent operation:

```bash
docker compose up -d --build
```

Do not use Flask debug mode when the web interface is accessible to other machines.

## 14. Updating the application

After changing Python dependencies:

```bash
docker compose up -d --build
```

After changing only HTML, CSS, or JavaScript in the normal non-mounted configuration:

```bash
docker compose up -d --build
```

View build details:

```bash
docker compose build --progress=plain
```

## 15. Stop and remove

Stop while retaining the image:

```bash
docker compose down
```

Remove the image as well:

```bash
docker compose down --rmi local
```

The application has no persistent database yet, so it currently does not require a Docker volume.

## Recommended architecture afterward

Do not put the whole SOAR system in one container. Use one service per responsibility:

```text
hawki-frontend
    │
    ├── hawki-tool-gateway
    ├── vllm
    ├── elasticsearch
    └── kibana
```

Each service can be managed by one `compose.yaml`, but each should remain a separate container. This preserves independent updates, health checks, resource limits, permissions, and network controls. Docker’s guidance favors separating concerns into separate services rather than running several major processes in one container. ([Docker Documentation][6])

[1]: https://docs.python.org/ko/3.10/library/venv.html?utm_source=chatgpt.com "venv — Creation of virtual environments — Python 3.10.20 문서"
[2]: https://docs.docker.com/reference/dockerfile?utm_source=chatgpt.com "Dockerfile reference | Docker Docs"
[3]: https://docs.docker.com/compose/gettingstarted/?utm_source=chatgpt.com "Docker Compose Quickstart | Docker Docs"
[4]: https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/?utm_source=chatgpt.com "Set environment variables within your container's environment | Docker Docs"
[5]: https://docs.docker.com/desktop/features/networking/networking-how-tos/?utm_source=chatgpt.com "Explore networking how-tos on Docker Desktop | Docker Docs"
[6]: https://docs.docker.com/engine/containers/multi-service_container/?utm_source=chatgpt.com "Run multiple processes in a container | Docker Docs"
