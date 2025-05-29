#    openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out cert.crt -keyout private.key

import http.server
import http.cookies
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
import ssl
import json
import threading
import socket
#_healthstatsus = 1

AppgatewayCookieName = 'ApplicationGatewayAffinity'
AppgatewayCORSCookieName = 'ApplicationGatewayAffinityCORS'
createAppGatewayCookie = False   # change to False if you are testing behind app Gateway!
SiteFQDN = "hsw1.abberley.wtf"


servers = []
serversettings  = ['a1','10.0.3.4',443,'server1.chain.crt','Server.key']
servers.append(serversettings)
serversettings  = ['a2','10.0.3.4',8443,'server1.chain.crt','Server.key']
servers.append(serversettings)
serversettings  = ['a1','10.0.3.5',443,'server1.chain.crt','Server.key']
servers.append(serversettings)
serversettings  = ['a2','10.0.3.5',8443,'server1.chain.crt','Server.key']
servers.append(serversettings)
#serversettings  = ['b1','192.168.4.99',443,'server1.chain.crt','Server.key']
#servers.append(serversettings)
#serversettings  = ['b2','192.168.4.99',8443,'server1.chain.crt','Server.key']
#servers.append(serversettings)

_healthstatus = {}
for webserver in servers:
    if webserver[0][1] == '2':
        _healthstatus[webserver[1]]= 0

# In-memory user database (for demonstration purposes)
USER_DB = {"admin": "pass","chris":"1234"}

# Session storage
SESSIONS = {}


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    global _healthstatus 

    #self.healthstatus = 0
    def do_GET(self):
        global _healthstatus 
        #self.healthstatus = 0
        #healthstatus = self.healthstatus
        # Extract cookies from the request
        session_id = "session_id= None"
        print(f'Host Header: {self.headers._headers[0][1]} , URI: {self.requestline}, REQUEST: {self.request}')
        if self.headers.get("Cookie") is not None:
            session_id = self.headers.get("Cookie")
        self.cookies = SimpleCookie(session_id)
        if self.path == '/imhere' or self.path =='/' or self.path =='':
            print(f'Cookie Session_ID: {self.cookies.get('session_id')}')
            if self.cookies.get('session_id').value  != 'None':
                if SESSIONS.get(self.cookies.get('session_id').value) is None:
                    SESSIONS[self.cookies.get('session_id').value] = ((self.cookies.get('session_id').value).split('-'))[1]
            if SESSIONS.get(self.cookies.get('session_id').value) is not None:
                self.username = SESSIONS[self.cookies.get('session_id').value]
                self.serverip=self.server.server_address #socket.gethostbyname(self.headers.get('Host').split(':')[0])
                self.serverhost = self.headers.get('Host').split(':')[0]
                self.send_response(200)
                if  _healthstatus[self.server.server_address[0]] == 1:
                    if self.cookies.get('serverlb') is not None:
                        cookie_update = SimpleCookie()
                        cookie_update['serverlb'] = self.server.server_address[0]
                        cookie_update['serverlb']['path'] = '/'
                        cookie_update['serverlb']['expires'] = 0
                        cookie_update['serverlb']['httponly'] = True
                        cookie_update['serverlb']['samesite'] = 'Strict'
                        cookie_update['serverlb']['secure'] = True
                        #print(cookie_update.output())
                        self.send_header("Set-Cookie", cookie_update.output(header='', sep=''))
                    if self.cookies.get(AppgatewayCookieName) is not None:
                        cookie_update = SimpleCookie()
                        cookie_update[AppgatewayCookieName] = self.server.server_address[0]
                        cookie_update[AppgatewayCookieName]['path'] = '/'
                        cookie_update[AppgatewayCookieName]['expires'] = 0
                        cookie_update[AppgatewayCookieName]['httponly'] = True
                        cookie_update[AppgatewayCookieName]['samesite'] = 'Strict'
                        cookie_update[AppgatewayCookieName]['secure'] = True
                        self.send_header("Set-Cookie", cookie_update.output(header='', sep=''))
                    if self.cookies.get(AppgatewayCORSCookieName) is not None:
                        cookie_update = SimpleCookie()
                        cookie_update[AppgatewayCORSCookieName] = self.server.server_address[0]
                        cookie_update[AppgatewayCORSCookieName]['path'] = '/'
                        cookie_update[AppgatewayCORSCookieName]['expires'] = 0
                        cookie_update[AppgatewayCORSCookieName]['httponly'] = True
                        cookie_update[AppgatewayCORSCookieName]['samesite'] = 'Strict'
                        cookie_update[AppgatewayCORSCookieName]['secure'] = True
                        self.send_header("Set-Cookie", cookie_update.output(header='', sep=''))
                
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                #self.wfile.write(bytes(f"I'm here on backend server:\n\rRequest Header Server: {self.serverhost}\nServer Host: {self.server.server_name}\nBackend Server IP: {self.serverip}","utf-8"))
                self.wfile.write(bytes('<html><head><title>Hyperspace Web Server testing page</title></head></html>','utf-8'))
                self.wfile.write(bytes('<body><h1>Backend Web Server details</h1>','utf-8'))
                self.wfile.write(b"<a href='/logout'>Logout</a>")
                self.wfile.write(bytes(f'<p>Session User Name           : {self.username}</p>','utf-8'))
                self.wfile.write(bytes(f'<p>Request Header Server       : {self.serverhost}</p>','utf-8'))
                self.wfile.write(bytes(f'<p>Backend Server IP           : {self.serverip}</p>','utf-8'))
                self.wfile.write(bytes(f'<p>Backend Server Name         : {self.server.server_name}</p>','utf-8'))
                self.wfile.write(bytes(f'<p>Backend Server Health Status: {_healthstatus[self.serverip[0]]}</p>','utf-8'))
                self.wfile.write(bytes('<h3>Cookie Information</h3><ul>','utf-8'))
                for key, morsel in self.cookies.items():
                    cookie_value = morsel.value
                    cookie_max_age = morsel['max-age'] if morsel['max-age'] else 'N/A'
                    self.wfile.write(bytes(f"<li>{key}: {cookie_value} (TTL: {cookie_max_age})</li>","utf-8"))
                self.wfile.write(bytes('</ul></body></html>','utf-8'))
            else:
                self.redirect_to_login()
                
        elif self.path == '/Hyperspace_PROD/health/healthHandler.ashx?mode=loadbalancer':
            # Respond with "I'm here"
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps({'Status': _healthstatus[self.server.server_address[0]]}),"utf-8"))
            #self.wfile.write(bytes(f"health status: {healthstatus}","utf-8"))
        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <form method="POST" action="/login">
                    <label>Username: <input type="text" name="username"></label><br>
                    <label>Password: <input type="password" name="password"></label><br>
                    <button type="submit">Login</button>
                </form>
            """)
        elif self.path == "/logout":
            session_id = self.headers.get("Cookie")
            if session_id in SESSIONS:
                del SESSIONS[session_id]
            self.redirect_to_login()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
                
    def do_POST(self):
        if self.path == "/login":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            form_data = parse_qs(post_data.decode("utf-8"))

            username = form_data.get("username", [None])[0]
            password = form_data.get("password", [None])[0]

            if username in USER_DB and USER_DB[username] == password:
                # Create a session
                session_id = f"session-{username}-{len(SESSIONS) + 1}"
                SESSIONS[session_id] = username
                create_cookie = SimpleCookie()
                create_cookie['session_id'] = session_id
                #create_cookie['session_id']['domain'] = '.abberley.wtf'
                create_cookie['session_id']['path'] = '/'
                create_cookie['session_id']['max-age'] = 3600
                create_cookie['session_id']['httponly'] = True
                create_cookie['session_id']['samesite'] = 'Strict'
                create_cookie['session_id']['secure'] = True
                print(create_cookie.output())
                self.send_response(302)
                self.send_header("Set-Cookie", create_cookie.output(header='', sep=''))
                self.send_header("Set-Cookie", f"serverlb={self.server.server_address[0]}; HttpOnly; Path=/; Max-Age=600; SameSite=Strict; Secure")
                if createAppGatewayCookie:
                    self.send_header("Set-Cookie", f"{AppgatewayCookieName}={self.server.server_address[0]}; HttpOnly; Path=/; Max-Age=600; SameSite=Strict; Secure")
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self.send_response(401)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Invalid credentials. <a href='/login'>Try again</a>.")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def redirect_to_login(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.end_headers()

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
    context.load_cert_chain(certfile=cert_fpath, keyfile=privkey_fpath) #, password='WdyWfm.2023')
    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, CustomHandler)
    httpd.server_name = SiteFQDN
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True) #, server_hostname=SiteFQDN)
    httpd.socket.server_hostname = SiteFQDN
    print(f"Starting HTTPS server on {host}:{port}.../n/r")
    httpd.serve_forever()

def serve_http(host):
    server_address = (host, 80)
    httpd = http.server.HTTPServer(server_address, CustomHandler)
    print(f"Starting HTTP server on {host}:80.../n/r")
    httpd.serve_forever()


def serve_admin(host):
    server_address = (host, 8012)
    httpd = http.server.HTTPServer(server_address, CustomHandlerAdmin)
    print(f"Starting admin HTTP server on {host}:8012.../n/r")
    httpd.serve_forever()


if __name__ == '__main__':
    thread={}

    skipserver1 = servers[0][0]
    for webserver in servers:
        if webserver[0] != skipserver1:
  
            thread[webserver[0]] = threading.Thread(target=serve, args=(webserver[1], webserver[2], webserver[3], webserver[4]))
            thread[webserver[0]].daemon = True
            thread[webserver[0]].start()
    
    admin_sites = list(_healthstatus.keys())
    for keys in admin_sites:
        thread[keys] = threading.Thread(target=serve_admin, args=(keys,))
        thread[keys].daemon = True
        thread[keys].start()
        thread[f'{keys}_http']= threading.Thread(target=serve_http, args=(keys,))
        thread[f'{keys}_http'].daemon = True
        thread[f'{keys}_http'].start()
        
    # Start the final server in the main thread
    serve(servers[0][1], servers[0][2], servers[0][3], servers[0][4])