# Certificate Tools

A React-based frontend application for managing SSL certificates with Azure AD authentication.

## Project Structure

```
certificate-tools/
├── docker-compose.yml     # Docker orchestration (stays at root)
└── frontend/             # All frontend code and configs
    ├── Dockerfile
    ├── package.json
    ├── README.md         # Detailed frontend documentation
    └── src/              # Source code
```

## Quick Start

1. **Setup environment:**
   ```bash
   cd frontend
   cp .env.example .env
   # Edit .env with your Azure AD credentials
   ```

2. **Development:**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

3. **Docker (from root):**
   ```bash
   docker-compose up --build
   ```

## Features

- Azure AD authentication integration
- Material-UI components with custom styling
- Docker containerization
- Role-based access control
- Responsive design

## Environment Setup

All environment variables should be configured in `frontend/.env`. See `frontend/.env.example` for required variables.

## Documentation

Detailed frontend documentation is available in `frontend/README.md`.