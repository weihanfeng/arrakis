from http.server import BaseHTTPRequestHandler, HTTPServer
import os

def get_server_ip():
    ip = os.getenv('SERVER_IP')
    if ip is None:
        raise ValueError('SERVER_IP environment variable is not set')
    if ip == '':
        raise ValueError('SERVER_IP environment variable is set but empty')
    return ip

class SimpleRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Hello World from a Python3 server\n')

def run():
    port = 3001
    try:
        hostname = get_server_ip()
        server_address = (hostname, port)
        httpd = HTTPServer(server_address, SimpleRequestHandler)
        print(f'Python HTTP Server running at http://{hostname}:{port}/')
        httpd.serve_forever()
    except Exception as e:
        print(f'Failed to start server: {str(e)}')
        exit(1)

if __name__ == '__main__':
    run()
