# Use a slim Python 3 base image
FROM python:3.10

# Set the working directory inside the container
WORKDIR /app

# Create a non-root user and group
RUN groupadd -r appuser && useradd -r -g appuser -s /sbin/nologin -c "Docker image user" appuser

# Create directories for output and logs, and set ownership
RUN mkdir /app/output /app/logs && chown -R appuser:appuser /app/output /app/logs 

# Copy requirements file
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and server keys
COPY src/ ./src/
COPY server.key ./server.key
COPY server.pub ./server.pub


# Ensure server.key as restricted permissions
RUN chmod 600 ./server.key && \
    chown appuser:appuser ./server.key ./server.pub ./src

# Switch to the non-root user
USER appuser

# Expose the SSH honeypot port
EXPOSE 2222

# Run the honeypot script
CMD ["python", "src/ssh_honeypot.py"]
