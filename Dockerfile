# Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . .

# Clone Sublist3r if not present
RUN if [ ! -d "Sublist3r" ]; then \
    git clone https://github.com/aboul3la/Sublist3r.git; \
    pip install --no-cache-dir -r Sublist3r/requirements.txt; \
    fi

# Create necessary directories
RUN mkdir -p templates

# Expose Flask port
EXPOSE 5000

# Start the app
CMD ["python", "dashboard.py"]