const http = require('http');

const PORT = process.env.PORT || 3002;

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);

  if (req.method === 'GET' && req.headers.accept?.includes('text/event-stream')) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });

    res.write('data: {"jsonrpc":"2.0","method":"endpoint","params":{"type":"endpoint","url":"/message"}}\n\n');

    const keepAlive = setInterval(() => {
      res.write(':keepalive\n\n');
    }, 30000);

    setTimeout(() => {
      res.write('data: {"jsonrpc":"2.0","method":"notification","params":{"type":"server_info","version":"1.0"}}\n\n');
    }, 1000);

    req.on('close', () => {
      clearInterval(keepAlive);
    });
  } else if (req.url === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Mock Streamable MCP Server');
  } else if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const request = JSON.parse(body);
        console.log('Received request:', request);

        if (!request.id) {
          res.writeHead(200);
          res.end();
          return;
        }

        const acceptHeader = req.headers.accept || '';
        const wantsSSE = acceptHeader.includes('text/event-stream');

        if (request.method === 'initialize') {
          const response = {
            jsonrpc: '2.0',
            id: request.id,
            result: {
              protocolVersion: '2025-06-18',
              capabilities: { tools: { listChanged: false } },
              serverInfo: { name: 'mock-streamable-server', version: '1.0.0' }
            }
          };
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(response));
        } else if (request.method === 'tools/list') {
          const response = {
            jsonrpc: '2.0',
            id: request.id,
            result: {
              tools: [
                {
                  name: 'get_time',
                  description: 'Get the current time',
                  inputSchema: {
                    type: 'object',
                    properties: {}
                  }
                },
                {
                  name: 'echo_streamable',
                  description: 'Echo text back',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      text: { type: 'string' }
                    },
                    required: ['text']
                  }
                }
              ]
            }
          };

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(response));
        } else if (request.method === 'tools/call') {
          if (request.params.name === 'get_time') {
            const response = {
              jsonrpc: '2.0',
              id: request.id,
              result: {
                content: [{ type: 'text', text: new Date().toISOString() }]
              }
            };
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(response));
          } else if (request.params.name === 'echo_streamable') {
            if (wantsSSE) {
              res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive'
              });

              const messages = [
                { jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: `Echo: ${request.params.arguments.text}` }] } },
                { jsonrpc: '2.0', method: 'notification', params: { message: 'Processing complete' } }
              ];

              messages.forEach((msg, index) => {
                setTimeout(() => {
                  res.write(`data: ${JSON.stringify(msg)}\n\n`);
                }, index * 100);
              });

              setTimeout(() => {
                res.end();
              }, 300);
            } else {
              const response = {
                jsonrpc: '2.0',
                id: request.id,
                result: {
                  content: [{ type: 'text', text: `Echo: ${request.params.arguments.text}` }]
                }
              };
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(response));
            }
          } else {
            const response = {
              jsonrpc: '2.0',
              id: request.id,
              error: {
                code: -32601,
                message: 'Tool not found'
              }
            };
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(response));
          }
        } else {
          const response = {
            jsonrpc: '2.0',
            id: request.id,
            result: {}
          };
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(response));
        }
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
  } else {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('Method not allowed');
  }
});

server.listen(PORT, () => {
  console.log(`Mock Streamable MCP server listening on port ${PORT}`);
});
