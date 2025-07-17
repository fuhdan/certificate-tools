# Certificate Analysis API

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-blue)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful, modular FastAPI backend for deep analysis, management, and validation of Public Key Infrastructure (PKI) components.

This tool goes beyond simple certificate decoding. It functions as an in-memory PKI toolkit that understands the relationships between components, validates them cryptographically, and helps you assemble and manage entire certificate chains.

## ✨ Core Features

-   **Multi-Format Analysis**: Decodes and analyzes a wide variety of formats:
    -   `PEM`, `DER`: Certificates, Private Keys, CSRs.
    -   `PKCS#12` (`.p12`, `.pfx`): Bundles containing certificates and private keys.
    -   `PKCS#7`: Certificate chains.
    -   `PKCS#8`: Private Keys (including encrypted).
-   **Intelligent PKI Hierarchy**: Automatically identifies the role of each component (Root CA, Intermediate CA, End-entity Certificate, Private Key, CSR) and organizes them in a logical hierarchy.
-   **Cryptographic Validation**: Performs crucial validation checks:
    -   Verifies that a private key matches a certificate's public key.
    -   Verifies that a private key matches a CSR's public key.
    -   Verifies that a certificate was issued from a CSR.
    -   Validates the signature and trust chain between certificates.
-   **Robust Duplicate Detection**: Uses normalized content hashing to reliably detect and manage duplicate files, even if they are in different formats (e.g., a key from a PEM file vs. the same key from a PKCS#12 file).
-   **Automatic PKI Bundle Generation**: Creates and provides a complete, ordered PKI bundle in a JSON format, containing all uploaded components as PEM strings. Ideal for deployment or sharing.
-   **Secure by Design**:
    -   Separates sensitive cryptographic objects from JSON-serializable data in memory.
    -   Uses JWT for secure API endpoint authentication.
    -   No sensitive data (like private key passwords) is ever stored or returned in API responses.

## 💻 Technology Stack

-   **Backend**: FastAPI
-   **Cryptography**: `cryptography` library
-   **Authentication**: `python-jose` for JWT, `passlib` for password hashing
-   **Server**: Uvicorn
-   **Containerization**: Docker

## 🚀 Getting Started

The recommended way to run the application is with Docker.

### Prerequisites

-   Docker and Docker Compose

### Running with Docker

1.  **Clone the repository.**
2.  Navigate to the root directory of the project.
3.  Run the application using Docker Compose (if a `docker-compose.yml` is provided) or build and run the backend image directly.

    ```bash
    # Build the backend image
    docker build -t cert-tools-backend-fastapi ./backend-fastapi

    # Run the container
    docker run -d --name cert-tools-api -p 8000:8000 cert-tools-backend-fastapi
    ```

4.  The API will be available at `http://localhost:8000`.
5.  Interactive API documentation (Swagger UI) is available at `http://localhost:8000/docs`.

### Local Development

1.  **Create a virtual environment:**
    ```bash
    python3.11 -m venv venv
    source venv/bin/activate
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r backend-fastapi/requirements.txt
    ```
3.  **Run the development server:**
    ```bash
    cd backend-fastapi
    uvicorn main:app --reload
    ```
4.  The API will be available at `http://localhost:8000`.

## ⚙️ Configuration

Application settings can be configured via environment variables. See `config.py` for all available options.

| Variable                      | Description                                           | Default                                |
| ----------------------------- | ----------------------------------------------------- | -------------------------------------- |
| `SECRET_KEY`                  | **Required for Production.** A strong, random secret. | `your-secret-key-change-in-production` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT token validity duration.                          | `30`                                   |
| `DEBUG`                       | Set to `ON` for debug mode and auto-reload.           | `OFF`                                  |
| `CORS_ORIGINS`                | Comma-separated list of allowed CORS origins.         | `*` (Not for production)               |

## 🏛️ Architectural Concepts

-   **In-Memory Storage**: The application uses in-memory storage for all uploaded data. **This means all data is lost on restart.** This design prioritizes speed and simplicity for temporary analysis sessions. For persistence, a database backend would be required.
-   **Crypto Object Separation**: Raw cryptographic objects (from the `cryptography` library) are stored separately from their JSON analysis results. This allows for fast, on-demand cryptographic operations (like validation) without re-parsing files.
-   **PKI Hierarchy Enforcement**: The system maintains a logical PKI set. For example, only one "End-entity Certificate" or one "Private Key" can exist at a time. Uploading a new one will automatically replace the old one, simplifying the management of a single PKI environment.

## 📖 API Endpoints

The base URL is `http://localhost:8000`. All endpoints under `/api/` are protected and require a Bearer Token.

### Authentication

-   **`POST /token`**
    -   **Description**: Authenticate and receive a JWT Bearer token.
    -   **Body**: `x-www-form-urlencoded` with `username` and `password`.
    -   **Default Credentials**: `username: admin`, `password: admin123`
    -   **Response**:
        ```json
        {
          "access_token": "ey...",
          "token_type": "bearer"
        }
        ```

### Certificate Management

-   **`POST /analyze-certificate`**
    -   **Description**: Upload and analyze a certificate file. Handles duplicates and unpacks bundles like PKCS#12.
    -   **Body**: `multipart/form-data` with `certificate: (file)` and optional `password: (string)`.
    -   **Success Response**:
        ```json
        {
          "success": true,
          "isDuplicate": false,
          "certificate": {
            "id": "...",
            "filename": "my-cert.crt",
            "analysis": { ... },
            "uploadedAt": "...",
            "size": 1234
          },
          "additional_items": [],
          "timestamp": "..."
        }
        ```
    -   **Password Required Response**:
        ```json
        {
          "success": false,
          "requiresPassword": true,
          "certificate": { ... },
          "message": "Password required for encrypted.key"
        }
        ```

-   **`GET /certificates`**
    -   **Description**: Retrieve a list of all uploaded and analyzed certificates, sorted by PKI hierarchy.
    -   **Response**:
        ```json
        {
          "success": true,
          "certificates": [ ... ],
          "count": 1
        }
        ```

-   **`DELETE /certificates/{certificate_id}`**
    -   **Description**: Delete a specific certificate by its unique ID.

-   **`DELETE /certificates`**
    -   **Description**: Clear all uploaded certificates and analysis data from memory.

### Validation & Statistics

-   **`GET /api/validate` (Protected)**
    -   **Description**: Runs all possible cryptographic validation checks on the currently stored set of certificates.
    -   **Response**:
        ```json
        {
          "success": true,
          "validations": [
            {
              "isValid": true,
              "validationType": "Private Key <-> Certificate",
              "details": { ... },
              "error": null
            }
          ],
          "count": 1,
          "timestamp": "..."
        }
        ```

-   **`GET /api/stats` (Protected)**
    -   **Description**: Get system and storage statistics.

### PKI Bundle

-   **`GET /api/pki-bundle` (Protected)**
    -   **Description**: Generates and retrieves a complete PKI bundle of all stored components.
    -   **Response**:
        ```json
        {
          "success": true,
          "bundle": {
            "version": "1.0",
            "generated": "...",
            "description": "...",
            "components": [
              {
                "fileType": "PrivateKey",
                "file": "-----BEGIN PRIVATE KEY-----\n...",
                "details": { ... }
              },
              {
                "fileType": "Certificate",
                "file": "-----BEGIN CERTIFICATE-----\n...",
                "details": { ... }
              }
            ]
          },
          "timestamp": "..."
        }
        ```

-   **`GET /api/pki-bundle/download` (Protected)**
    -   **Description**: Downloads the generated PKI bundle as a `pki-bundle.json` file.

-   **`GET /api/pki-bundle/validation` (Protected)**
    -   **Description**: Validates the completeness of the current PKI bundle.

### Health

-   **`GET /health`**
    -   **Description**: Simple health check endpoint.
    -   **Response**:
        ```json
        {
          "status": "online",
          "timestamp": "...",
          "uptime": 123
        }
        ```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a pull request.

1.  Fork the repository.
2.  Create a new feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add some amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a pull request.

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.
