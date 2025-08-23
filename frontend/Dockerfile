FROM node:24-alpine AS builder

WORKDIR /app

# Accept build arguments for Vite environment variables
ARG VITE_API_URL=/api
ARG VITE_DEBUG=false
ARG VITE_LOG_LEVEL=INFO

# Set environment variables from build args
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_DEBUG=$VITE_DEBUG
ENV VITE_LOG_LEVEL=$VITE_LOG_LEVEL

COPY package.json ./
RUN npm install
RUN npm install react-router-dom

COPY . .
RUN npm run build

# Simple static file server using Node.js serve (NO NGINX)
FROM node:24-alpine

WORKDIR /app

# Install serve to serve static files
RUN npm install -g serve

# Copy built files from builder stage
COPY --from=builder /app/dist /app/dist
COPY logo.png /app/dist/logo.png

EXPOSE 3000

# Serve the built React app on port 3000
CMD ["serve", "-s", "/app/dist", "-l", "3000"]