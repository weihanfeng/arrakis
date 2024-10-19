const { createServer } = require('node:http');

// Function to get the IP address from environment variable
function getServerIp() {
  const ip = process.env.SERVER_IP;
  if (ip === undefined) {
    throw new Error('SERVER_IP environment variable is not set');
  }
  if (ip === '') {
    throw new Error('SERVER_IP environment variable is set but empty');
  }
  return ip;
}

const port = 3000;
try {
  const hostname = getServerIp();

  const server = createServer((req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain');
    res.end('Hello World from a Node server\n');
  });

  server.listen(port, hostname, () => {
    console.log(`Node Server running at http://${hostname}:${port}/`);
  });
} catch (error) {
  console.error('Failed to start server:', error.message);
  process.exit(1);
}