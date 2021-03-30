from http.server import HTTPServer, BaseHTTPRequestHandler
import numpy

class MyWebServer(BaseHTTPRequestHandler):
    def do_GET(self):
        a = numpy.arange(25).reshape(5, 5)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>Mystikos Python Web Server</title></head>", "utf-8"))
        self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
        self.wfile.write(bytes("<body>", "utf-8"))
        self.wfile.write(bytes("<p>Hello world from Python Web Server.</p>", "utf-8"))
        self.wfile.write(bytes("<p>" + numpy.array2string(a) + "</p>", "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))
        self.wfile.write(bytes("\n", "utf-8"))

def run(server_class=HTTPServer, handler_class=MyWebServer):
    server_address = ("0.0.0.0", 8000)
    httpd = server_class(server_address, handler_class)
    print("launching server...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
