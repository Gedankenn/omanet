FROM alpine:3.20

RUN apk add --no-cache python3 arp-scan iproute2 tzdata

WORKDIR /app
COPY app.py names.json ./
COPY static ./static

ENV PORT=20211 SCAN_INTERVAL=60 TZ=America/Sao_Paulo

EXPOSE 20211
CMD ["python3", "/app/app.py"]
