FROM node:20-alpine

WORKDIR /app

# Install dependencies (layer cache)
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY . .

# Uploads directory
RUN mkdir -p public/uploads && chmod 777 public/uploads

EXPOSE 3000

# Wait for DB → seed → start
CMD ["sh", "-c", "sleep 8 && node database/seed.js && node server.js"]
