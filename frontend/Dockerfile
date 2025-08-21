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

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY logo.png /usr/share/nginx/html/logo.png
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]