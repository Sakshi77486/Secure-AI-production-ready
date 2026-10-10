# Secure AI — AI-Powered Code Security Scanner

**Find potential code vulnerabilities. Understand the risk. Get AI-assisted guidance to fix them.**

Secure AI is a developer-focused security scanning project designed to help developers identify potential vulnerabilities in source code and understand how to address them. It combines static-analysis tooling with AI-assisted explanations to make security findings easier to investigate.

The project brings together a Python API backend, a web frontend, database infrastructure, and code-analysis dependencies in a single repository.

> **Project status:** Under active development. Security findings require developer review and validation; AI-generated recommendations should not be treated as a guarantee that code is secure.

## 🎯 Problem Statement

Security issues can be difficult to identify and interpret, particularly for developers who are still learning secure coding practices. Raw scanner findings may also require additional context before a developer can decide what to fix.

Secure AI aims to bridge that gap by combining code analysis with explanations that help developers understand potential issues and consider remediation options.

## ✨ Core Capabilities

- **Code Security Analysis** — Uses code-analysis tooling to help identify potential security issues.
- **Risk Assessment** — Organizes security findings for further investigation and prioritization, according to the implemented analysis workflow.
- **AI-Assisted Explanations** — Integrates an AI provider to help explain security findings and their potential implications.
- **Remediation Guidance** — Supports AI-assisted suggestions for addressing detected issues.
- **Backend API** — Uses FastAPI to provide a foundation for application endpoints and security-analysis workflows.
- **Persistent Data Layer** — Includes PostgreSQL and SQLAlchemy dependencies for database-backed functionality.
- **Asynchronous Processing Infrastructure** — Includes Celery and Redis dependencies for background-job workflows.
- **Web Application** — Provides a separate frontend for interacting with the application.

*The exact coverage and availability of each capability depend on the current implementation and configuration.*

## 🧰 Technology Stack

| Component | Technology |
|---|---|
| Frontend | React ecosystem, JavaScript |
| Backend API | Python, FastAPI, Uvicorn |
| Code analysis | Semgrep, Tree-sitter |
| AI integration | Anthropic API |
| Database | PostgreSQL, SQLAlchemy |
| Background jobs | Celery, Redis |
| Authentication and security dependencies | JWT-related libraries, password-hashing libraries |
| Testing | pytest, pytest-asyncio, HTTPX |
| Infrastructure | Docker Compose |

The stack above is based on the repository's dependency and configuration files. It does not imply that every listed dependency is already connected to a complete, tested production workflow.

## 🏗️ Architecture

```text
Developer
    │
    ▼
Web Frontend
    │
    ▼
FastAPI Backend
    │
    ├── Code Analysis
    │     ├── Semgrep
    │     └── Tree-sitter
    │
    ├── AI-Assisted Analysis
    │     └── Anthropic API
    │
    ├── Database Layer
    │     └── PostgreSQL / SQLAlchemy
    │
    └── Background Job Infrastructure
          └── Celery / Redis
```

## 📁 Repository Structure

```text
Secure-AI-production-ready/
├── backend/
├── frontend/
├── .env.example
├── .gitignore
├── docker-compose.yml
├── package.json
├── package-lock.json
├── requirements.txt
└── README.md
```

## ⚙️ Getting Started

### Prerequisites

- Python compatible with the backend dependencies
- Node.js and npm
- PostgreSQL, or Docker Desktop for the supplied database configuration
- An Anthropic API key if the configured AI features require it

### 1. Clone the repository

```bash
git clone https://github.com/Sakshi77486/Secure-AI-production-ready.git
cd Secure-AI-production-ready
```

### 2. Configure environment variables

Review `.env.example` to identify the environment variables required by the application.

Create a local `.env` file from the example and fill in the values required by your configuration. Never commit real API keys, database credentials, or other secrets.

### 3. Install backend dependencies

```bash
python -m venv .venv
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

On Git Bash:

```bash
source .venv/Scripts/activate
```

Install the listed dependencies:

```bash
pip install -r requirements.txt
```

Start the API using the actual FastAPI application module and entry point defined in the `backend/` directory.

### 4. Configure the database

Review `docker-compose.yml` and `.env.example` to understand the database configuration.

If using the supplied Compose configuration, ensure Docker Desktop is running, review the development credentials, and start the database service:

```bash
docker compose up -d postgres
```

Use the application's configured database URL and follow any migration or initialization steps implemented in the backend.

**Security note:** The supplied Compose file includes development database credentials. Replace them for any shared or deployed environment, and never reuse development credentials in production.

### 5. Install frontend dependencies

From the repository root:

```bash
npm install
```

Then follow the frontend's own scripts and configuration to start the web application. Check `frontend/package.json` for the correct development command.

### 6. Verify the application

Once the required services are configured and running:

- Confirm that the backend starts successfully.
- Verify the API routes exposed by the application.
- Confirm that the frontend can reach the backend.
- Test the code-analysis workflow with a small, non-sensitive sample.
- Review the resulting findings and validate remediation suggestions independently.

## 🔐 Security Considerations

- Store API keys and secrets in environment variables.
- Validate and restrict uploaded code and file types.
- Treat source code submitted for analysis as potentially sensitive.
- Avoid logging secrets or unnecessary source-code contents.
- Apply authentication and authorization to protected endpoints.
- Review AI-generated recommendations before applying changes.
- Run security tests and dependency checks before deployment.

## 🧪 Testing

The repository includes testing dependencies such as pytest and HTTPX.

To run the project's test suite, use the tests and commands actually provided by the codebase. Add documented test commands and verified coverage as the test suite becomes established.

## 🚧 Future Improvements

Potential directions for further development include:

- Repository-level scanning and multi-file analysis
- More detailed vulnerability severity and prioritization
- Improved source-code context for AI-generated remediation
- Scan history and comparison of findings
- Automated security regression tests
- CI/CD integration
- More comprehensive authentication, authorization, and audit logging
- Reproducible deployment and monitoring

These are proposed improvements, not claims about already implemented functionality.

## 👩‍💻 Author

**Sakshi Jain**

BCA Student | Aspiring Software Engineer | AI & Application Security

- GitHub: [@Sakshi77486](https://github.com/Sakshi77486)
- Project repository: [Secure-AI-production-ready](https://github.com/Sakshi77486/Secure-AI-production-ready)

## 📄 License

A license has not been verified here. Add an appropriate `LICENSE` file if you intend to specify how others may use, modify, and distribute this project.
