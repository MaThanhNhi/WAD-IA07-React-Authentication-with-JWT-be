# Render.com Build Script for NestJS Backend
# This script runs during deployment on Render

#!/bin/bash
set -e  # Exit on error

echo "🚀 Starting build process..."

# Install dependencies
echo "📦 Installing dependencies..."
pnpm install --frozen-lockfile

# Build the application
echo "🔨 Building NestJS application..."
pnpm run build

# Generate Prisma Client
echo "🔧 Generating Prisma Client..."
npx prisma generate

# Run database migrations
echo "🗄️ Running database migrations..."
npx prisma migrate deploy

echo "✅ Build completed successfully!"
