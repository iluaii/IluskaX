# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o luska ./main.go
RUN go build -o pentest ./cmd/pentest/main1.go

# Final stage
FROM python:3.12-slim

WORKDIR /root

# System deps
RUN apt-get update && apt-get install -y \
    curl \
    git \
    wget \
    unzip \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Go runtime (нужен для установки инструментов через go install)
COPY --from=golang:1.24-alpine /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# dalfox
RUN go install -v github.com/hahwul/dalfox/v2@latest

# sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py

# Copy built binaries from builder
COPY --from=builder /app/luska /usr/local/bin/luska
COPY --from=builder /app/pentest /usr/local/bin/pentest

# Output dirs
RUN mkdir -p /root/output /root/Poutput

WORKDIR /root

CMD ["luska", "--help"]
