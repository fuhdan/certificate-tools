FROM node:24-alpine AS builder

WORKDIR /app
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