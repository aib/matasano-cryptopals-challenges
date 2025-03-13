import base64
import hashlib
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler
import time
from urllib.parse import urlparse, parse_qsl

SECRET_KEY = b'YELLOW SUBMARINE'

def digest(msg):
	dg = hmac.digest(SECRET_KEY, msg.encode('utf-8'), hashlib.sha1)
	return base64.b16encode(dg).decode('ascii').lower()

def insecure_compare(s1, s2):
	for (c1, c2) in zip(s1, s2, strict=True):
#		time.sleep(0.050)
		time.sleep(0.005)
		if c1 != c2:
			return False
	return True

class RequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		parsed = urlparse(self.path)
		query = dict(parse_qsl(parsed.query))

		if parsed.path == '/test':
			self.do_test(query)
		else:
			self.send_error(404)

	def do_test(self, query):
		dg = digest(query['file'])
		if insecure_compare(dg, query['signature']):
			self.send_response(200)
			self.end_headers()
		else:
			self.send_error(500)

def main():
	httpd = HTTPServer(('127.0.0.1', 9000), RequestHandler)
	httpd.serve_forever()

if __name__ == '__main__':
	main()
