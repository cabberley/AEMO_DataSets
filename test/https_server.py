#    openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out cert.crt -keyout private.key

import http.server
import http.cookies
import ssl
import json
import threading
import socket
#_healthstatsus = 1

servers = []
serversettings  = ['a1','192.168.4.137',443,'hsw1.crt','hsw1.key']
servers.append(serversettings)
serversettings  = ['a2','192.168.4.137',8443,'hsw1.crt','hsw1.key']
servers.append(serversettings)
serversettings  = ['b1','192.168.4.99',443,'hsw1.crt','hsw1.key']
servers.append(serversettings)
serversettings  = ['b2','192.168.4.99',8443,'hsw1.crt','hsw1.key']
servers.append(serversettings)

_healthstatus = {}
for webserver in servers:
    if webserver[0][1] == '2':
        _healthstatus[webserver[1]]= 0


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    global _healthstatus 

    #self.healthstatus = 0
    def do_GET(self):
        global _healthstatus 
        #self.healthstatus = 0
        #healthstatus = self.healthstatus
        # Extract cookies from the request
        cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))
        if self.path == '/imhere' or self.path =='/':
            # Respond with "I'm here"
            self.serverip=self.server.server_address #socket.gethostbyname(self.headers.get('Host').split(':')[0])
            self.serverhost = self.headers.get('Host').split(':')[0]
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            #self.wfile.write(bytes(f"I'm here on backend server:\n\rRequest Header Server: {self.serverhost}\nServer Host: {self.server.server_name}\nBackend Server IP: {self.serverip}","utf-8"))
            self.wfile.write(bytes('<html><head><title>Hyperspace Web Server testing page</title></head>','utf-8'))
            self.wfile.write(bytes('<body><h1>Backend Web Server details</h1>','utf-8'))
            self.wfile.write(bytes(f'<p>Request Header Server       : {self.serverhost}</p>','utf-8'))
            self.wfile.write(bytes(f'<p>Backend Server IP           : {self.serverip}</p>','utf-8'))
            self.wfile.write(bytes(f'<p>Backend Server Name         : {self.server.server_name}</p>','utf-8'))
            self.wfile.write(bytes(f'<p>Backend Server Health Status: {_healthstatus[self.serverip[0]]}</p>','utf-8'))
            self.wfile.write(bytes('<h3>Cookie Information</h3><ul>','utf-8'))
            for key, morsel in cookies.items():
                cookie_value = morsel.value
                cookie_max_age = morsel['max-age'] if morsel['max-age'] else 'N/A'
                self.wfile.write(bytes(f"<li>{key}: {cookie_value} (TTL: {cookie_max_age})</li>","utf-8"))
            self.wfile.write(bytes('</ul></body></html>','utf-8'))
        elif self.path == '/Hyperspace_PROD/health/healthHandler.ashx?mode=loadbalancer':
            # Respond with "I'm here"
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps({'Status': _healthstatus[self.server.server_address[0]]}),"utf-8"))
            #self.wfile.write(bytes(f"health status: {healthstatus}","utf-8"))
        else:
            # Default behavior for other paths
            super().do_GET()    


class CustomHandlerAdmin(http.server.SimpleHTTPRequestHandler):
    global _healthstatus 

    #self.healthstatus = 0
    def do_GET(self):            
        if self.path == '/admin':
            # Display admin page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(bytes('<html><head><title>Admin Page</title></head>', 'utf-8'))
            self.wfile.write(bytes('<body><h1>Admin Page</h1>', 'utf-8'))
            self.wfile.write(bytes('<form method="POST" action="/admin">', 'utf-8'))
            for key, value in _healthstatus.items():
                self.wfile.write(bytes(f'<label for="{key}">{key} (Current Value: {value}): </label>', 'utf-8'))
                self.wfile.write(bytes(f'<select name="{key}" id="{key}">', 'utf-8'))
                for option in ['0', '1', '2']:
                    selected = 'selected' if str(value) == option else ''
                    self.wfile.write(bytes(f'<option value="{option}" {selected}>{option}</option>', 'utf-8'))
                self.wfile.write(bytes('</select><br>', 'utf-8'))
            self.wfile.write(bytes('<input type="submit" value="Update"></form>', 'utf-8'))
            self.wfile.write(bytes('</body></html>', 'utf-8'))
        else:
            self.send_response(301)
            self.send_header('Location','/admin')
            self.end_headers()
            
    def do_POST(self):
        global _healthstatus
        if self.path == '/admin':
            # Handle form submission
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = dict(param.split('=') for param in post_data.split('&'))

            # Update _healthstatus dictionary
            for key, value in params.items():
                if key in _healthstatus and value in ['0','1', '2']:
                    _healthstatus[key] = int(value)

            # Redirect back to the admin page
            self.send_response(303)
            self.send_header('Location', '/admin')
            self.end_headers()





def serve(host, port, cert_fpath, privkey_fpath):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Might need to use ssl.PROTOCOL_TLS for older versions of Python
    context.load_cert_chain(certfile=cert_fpath, keyfile=privkey_fpath, password='WdyWfm.2023')
    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, CustomHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"Starting HTTPS server on {host}:{port}.../n/r")
    httpd.serve_forever()

def serve_admin(host):
    server_address = (host, 8012)
    httpd = http.server.HTTPServer(server_address, CustomHandlerAdmin)
    print(f"Starting admin HTTP server on {host}:8012.../n/r")
    httpd.serve_forever()


if __name__ == '__main__':
    thread={}
    # First HTTPS server on port 443
    PORT1 = 443
    CERT_FPATH1 = 'hsw1.crt'
    PRIVKEY_FPATH1 = 'hsw1.key'

    # Second HTTPS server on port 8443
    PORT2 = 8443
    CERT_FPATH2 = 'hsw1.crt'
    PRIVKEY_FPATH2 = 'hsw1.key'

    skipserver1 = servers[0][0]
    for webserver in servers:
        if webserver[0] != skipserver1:
  
            thread[webserver[0]] = threading.Thread(target=serve, args=(webserver[1], webserver[2], webserver[3], webserver[4]))
            thread[webserver[0]].daemon = True
            thread[webserver[0]].start()
    
    admin_sites = list(_healthstatus.keys())
    for keys in admin_sites:
        #serve_admin(key)
        thread[keys] = threading.Thread(target=serve_admin, args=(keys,))
        thread[keys].daemon = True
        thread[keys].start()

    # Start the final server in the main thread
    serve(servers[0][1], servers[0][2], servers[0][3], servers[0][4])