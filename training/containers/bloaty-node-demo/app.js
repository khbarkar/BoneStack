const http = require("http");

const server = http.createServer((_, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("bloaty node demo\n");
});

server.listen(3000);
