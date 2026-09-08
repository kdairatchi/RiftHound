import threading
from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import urlparse,parse_qs
from rifthound.core_engine import Engine

class H(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  p=urlparse(self.path);q=parse_qs(p.query)
  if p.path=='/reflect':body=f'<html><body>{q.get("q",[""])[0]}</body></html>'.encode()
  elif p.path=='/pm':body=b'<script>window.addEventListener("message",e=>document.body.innerHTML=e.data.html)</script>'
  else:body=b'ok'
  self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(body)

def test_native_reflection_and_pm():
 s=HTTPServer(('127.0.0.1',0),H);t=threading.Thread(target=s.serve_forever,daemon=True);t.start();port=s.server_port
 try:
  e=Engine([f'http://127.0.0.1:{port}/reflect?q=hello',f'http://127.0.0.1:{port}/pm'],threads=2,rps=0)
  rows=e.run({'reflection','dom'})
  assert any(x['family']=='XSS' and x['parameter']=='q' for x in rows)
  assert any(x['family']=='POSTMESSAGE' for x in rows)
 finally:s.shutdown();s.server_close()
