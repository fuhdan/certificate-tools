FROM node:22.16.0-slim

WORKDIR /app

# Install OpenSSL for certificate operations
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application files
COPY . .

# Expose port
EXPOSE 3001

# Start the application
CMD ["npm", "start"]