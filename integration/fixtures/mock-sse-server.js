const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3001;

// Map of sessionId -> SSE response writer
const sessions = new Map();

function handleRequest(request) {
  if (request.method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id: request.id,
      result: {
        protocolVersion: '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'mock-sse-server', version: '1.0.0' }
      }
    };
  }

  if (request.method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id: request.id,
      result: {
        tools: [
          {
            name: 'echo_text',
            description: 'Echo the provided text',
            inputSchema: {
              type: 'object',
              properties: {
                text: { type: 'string' }
              },
              required: ['text']
            }
          },
          {
            name: 'sample_stream',
            description: 'Sample streaming tool',
            inputSchema: {
              type: 'object',
              properties: {}
            }
          }
        ]
      }
    };
  }

  if (request.method === 'tools/call') {
    if (request.params.name === 'echo_text') {
      return {
        jsonrpc: '2.0',
        id: request.id,
        result: {
          content: [{ type: 'text', text: request.params.arguments.text }]
        }
      };
    }
    if (request.params.name === 'non_existent_tool_xyz') {
      return {
        jsonrpc: '2.0',
        id: request.id,
        error: {
          code: -32601,
          message: 'Tool not found: ' + request.params.name
        }
      };
    }
    return {
      jsonrpc: '2.0',
      id: request.id,
      result: {
        content: [{ type: 'text', text: 'Tool executed successfully' }]
      }
    };
  }

  return {
    jsonrpc: '2.0',
    id: request.id,
    result: {}
  };
}

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);

  if (req.url === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Mock SSE MCP Server');
    return;
  }

  if (req.url === '/sse' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });

    const sessionId = crypto.randomUUID();
    sessions.set(sessionId, res);

    res.write(`event: endpoint\ndata: /message?sessionId=${sessionId}\r\n\r\n`);

    const keepAlive = setInterval(() => {
      res.write(':keepalive\n\n');
    }, 30000);

    req.on('close', () => {
      clearInterval(keepAlive);
      sessions.delete(sessionId);
    });
    return;
  }

  if (req.url.startsWith('/message') && req.method === 'POST') {
    const urlObj = new URL(req.url, `http://localhost:${PORT}`);
    const sessionId = urlObj.searchParams.get('sessionId');

    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const request = JSON.parse(body);
        console.log('Received request:', request);

        // Notifications have no id - just acknowledge
        if (!request.id) {
          res.writeHead(202);
          res.end();
          return;
        }

        const response = handleRequest(request);
        const sseRes = sessionId ? sessions.get(sessionId) : null;

        if (sseRes) {
          // Deliver via SSE stream (mcp-go SSE clients read responses from the stream)
          const data = JSON.stringify(response);
          sseRes.write(`event: message\ndata: ${data}\r\n\r\n`);
        }

        // Return response in POST body (direct proxy clients read from the body)
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
      } catch (e) {
        console.error('Error processing request:', e);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32700,
            message: 'Parse error'
          }
        }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`Mock SSE MCP server listening on port ${PORT}`);
});
