FROM node:20-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y git curl build-essential
RUN mkdir -p /var/cache/demo && dd if=/dev/zero of=/var/cache/demo/fake-artifact.bin bs=1M count=20

COPY package.json package-lock.json ./
RUN npm install
RUN npm cache verify || true

COPY app.js ./

CMD ["node", "app.js"]
