# Certificate Tools - Frontend

[![React](https://img.shields.io/badge/React-18.2.0-blue.svg)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-4.5.0-purple.svg)](https://vitejs.dev/)
[![Nginx](https://img.shields.io/badge/Nginx-alpine-brightgreen.svg)](https://www.nginx.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This is the frontend for the **Certificate Analysis API**, a modern and responsive single-page application (SPA) built with React and Vite. It provides a rich user interface for uploading, analyzing, validating, and managing Public Key Infrastructure (PKI) components.

## ✨ Features

-   **Intuitive File Upload**: Drag-and-drop interface for uploading certificate files (`.pem`, `.crt`, `.der`, `.p12`, `.pfx`, `.key`, `.csr`, etc.).
-   **Encrypted File Support**: Prompts for a password when an encrypted private key or PKCS#12 bundle is uploaded.
-   **Detailed Analysis Views**: Presents parsed certificate, CSR, and private key data in a clean, hierarchical, and easy-to-read format.
-   **Cryptographic Validation Panel**: Automatically runs validation checks (e.g., "does this private key match this CSR?") and displays the results in a user-friendly, expandable panel.
-   **Smart PKI Hierarchy Display**: Intelligently identifies and labels the role of each certificate (End-entity, Intermediate CA, Root CA).
-   **System Side Panel**: A floating panel that provides:
    -   Real-time backend connection status.
    -   A file manager to view and delete all uploaded items.
    -   A button to clear the entire session.
-   **Secure Authentication**: JWT-based login system to access protected features like the PKI Bundle viewer.
-   **PKI Bundle Viewer**: A modal that fetches the complete, ordered PKI bundle from the backend and displays it as formatted JSON, with options to copy or download.

## 💻 Technology Stack

-   **UI Library**: React
-   **Build Tool**: Vite
-   **HTTP Client**: Axios
-   **Icons**: Lucide React
-   **Styling**: CSS Modules
-   **Web Server**: Nginx (for production container)

## 📂 Project Structure

The project follows a standard component-based architecture. Key directories and files are outlined below:

frontend/ ├── dist/ # Build output directory ├── public/ # Static assets (not present, but a standard location) ├── src/ │ ├── components/ # Reusable React components │ │ ├── CertificateDetails/ # Displays details of a single PKI item │ │ ├── FileUpload/ # Handles file upload and analysis requests │ │ ├── FloatingPanel/ # The system side panel and its sub-components │ │ ├── Footer/ # Application footer │ │ ├── Header/ # Application header with login dropdown │ │ ├── Layout/ # Main layout orchestrating all components │ │ └── ValidationPanel/ # Displays cryptographic validation results │ ├── services/ │ │ └── api.js # Configured Axios instance for backend communication │ ├── App.jsx # Root React component │ ├── index.css # Global styles │ └── main.jsx # Application entry point ├── .gitignore ├── Dockerfile # Defines the production build and Nginx container ├── index.html # Main HTML entry point for Vite ├── nginx.conf # Nginx configuration for the production container ├── package.json # Project dependencies and scripts └── vite.config.js # Vite configuration


## 🚀 Getting Started

You can run the frontend using Docker (recommended for production-like setup) or locally for development.

### Prerequisites

-   Node.js (v18 or later) and npm
-   Docker and Docker Compose (for containerized setup)
-   A running instance of the `backend-fastapi` service.

### Running with Docker (as part of `docker-compose`)

The project is designed to be run with the main `docker-compose.yml` in the root directory.

1.  Navigate to the project's root directory.
2.  Run the command:
    ```bash
    docker-compose up --build
    ```
3.  The frontend will be available at `http://localhost:80`. API requests to `/api` will be automatically proxied to the backend container by Nginx.

### Running for Local Development

1.  **Navigate to the `frontend` directory:**
    ```bash
    cd frontend
    ```
2.  **Install dependencies:**
    ```bash
    npm install
    ```
3.  **Run the development server:**
    ```bash
    npm run dev
    ```
4.  The application will be running on `http://localhost:5173` (or another port if 5173 is in use).

    **Note on API Proxying**: For local development, you need to configure Vite's proxy to forward API calls to your running backend instance (e.g., `http://localhost:8000`). Add the following `server` configuration to your `frontend/vite.config.js` file:

    ```javascript
    // vite.config.js
    export default defineConfig({
      plugins: [react()],
      server: {
        proxy: {
          '/api': {
            target: 'http://localhost:8000', // Your backend URL
            changeOrigin: true,
            rewrite: (path) => path.replace(/^\/api/, '')
          },
           '/token': { // Also proxy the login endpoint
            target: 'http://localhost:8000',
            changeOrigin: true,
          },
           '/health': { // Also proxy the health endpoint
            target: 'http://localhost:8000',
            changeOrigin: true,
          }
        }
      }
    });
    ```

## 🏛️ Architectural Concepts

-   **Component-Based**: The UI is built from small, independent, and reusable React components.
-   **State Management**: The application currently uses a combination of React's built-in state (`useState`) and the `window` object for global events and functions to enable cross-component communication. A potential refactoring could involve using React's **Context API** to create a more robust and maintainable state management solution.
-   **API Service**: A centralized Axios instance in `src/services/api.js` handles all communication with the backend. It uses **interceptors** to automatically attach the JWT authentication token to requests and to handle 401 (Unauthorized) responses by logging the user out.

