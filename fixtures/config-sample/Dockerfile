# Dockerfile for CBOMScan testing

# Base image with crypto libraries (should be flagged)
FROM python:3.11-slim

# Alternative base images that would be flagged
# FROM ubuntu:22.04
# FROM node:18-alpine
# FROM golang:1.21

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose port
EXPOSE 8000

# Run application
CMD ["python", "app.py"]