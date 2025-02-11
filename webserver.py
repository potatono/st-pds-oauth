import http.server
import urllib
import urllib.parse
import json
import threading
import traceback

class WebServer:
    def __init__(self, app):
        self.config = app.config
        self.log = app.log
        self.map = {}

        self.init()

    def init(self):
        address = self.config.get("DEFAULT", "address", fallback="0.0.0.0")
        port = self.config.getint("DEFAULT", "port", fallback=9000)

        class RequestHandler(http.server.BaseHTTPRequestHandler):
            def respond(this, response, type, code=200):
                this.send_response(code)
                this.send_header('Content-type', type)
                this.end_headers()
                this.wfile.write(response.encode())
                this.wfile.write("\n".encode())

            def do(this, method):
                try:
                    response = self.handle_webserver_request(method, this.path)
                    if response:
                        if type(response) is dict:
                            this.respond(json.dumps(response), 'application/json')
                        else:
                            this.respond(response, 'text/html')
                    else:
                        this.respond("Not Found", "text/plain", 404)

                except Exception as ex:
                    # include traceback information
                    self.log.error(ex)
                    self.log.error(traceback.format_exc())
                    this.respond(str(ex), "text/plain", 500)

            def do_GET(this):
                this.do("GET")

            def do_POST(this):
                this.do("POST")

        self.webserver = http.server.ThreadingHTTPServer((address, port), RequestHandler)
        self.webthread = threading.Thread(target=self.run_webserver)

    def add_mapping(self, method, path, handler):
        self.map[(method, path)] = handler

    def run_webserver(self):
        self.log.info(f"Starting webserver on {self.webserver.server_address}...")
        self.webserver.serve_forever()

    def handle_webserver_request(self, method, path):
        parsed_url = urllib.parse.urlparse(path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if (method, path) in self.map:
            return self.map[(method, path)](query)

        return None
    
    def start(self):
        self.webthread.start()

    def shutdown(self):
        self.webserver.shutdown()
        self.webthread.join()