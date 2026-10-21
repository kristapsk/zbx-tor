import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch
import urllib.error
import http.server
import threading

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tor', ROOT/'scripts/tor_prometheus.py')
tor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tor)
FIXTURE = (ROOT/'tests/metrics.prom').read_text()

class Response(io.BytesIO):
    status = 200

class CollectorTests(unittest.TestCase):
    def test_real_http_and_redirect_rejection(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            redirect = False
            requests = []
            def do_GET(self):
                self.requests.append(self.path)
                if self.redirect:
                    self.send_response(302)
                    self.send_header('Location', '/other')
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(FIXTURE.encode())
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            port = str(server.server_port)
            self.assertIn('zbx_tor_metrics_ok 1\n', tor.collect(port))
            Handler.redirect = True
            out = tor.collect(port)
            self.assertIn('zbx_tor_metrics_ok 0\n', out)
            self.assertIn('zbx_tor_http_status 302\n', out)
            self.assertEqual(Handler.requests, ['/metrics', '/metrics'])
        finally:
            server.shutdown()
            worker.join()
            server.server_close()

    def fetch(self, payload, status=200):
        response = Response(payload)
        response.status = status
        with patch('urllib.request.OpenerDirector.open', return_value=response):
            return tor.collect('9035')

    def test_success(self):
        out = self.fetch(FIXTURE.encode())
        self.assertIn('zbx_tor_metrics_ok 1\n', out)
        self.assertIn('zbx_tor_http_status 200\n', out)
        self.assertEqual(len(re.findall('^# TYPE tor_hs_intro_established_count ',out,re.M)),1)
        self.assertIn('zbx_tor_socket_limit 65504\n',out)
        self.assertIn('tor_relay_load_socket_total{state="opened"} 10\n',out)

    def test_failures_have_no_fabricated_tor_values(self):
        for payload,status in [(b'',200),(b'<html>error</html>',200),(b'bad',503),(b'x'*(tor.MAX_BYTES+1),200)]:
            with self.subTest(status=status,size=len(payload)):
                out=self.fetch(payload,status)
                self.assertIn('zbx_tor_metrics_ok 0\n',out)
                self.assertNotRegex(out,r'(?m)^tor_')

    def test_http_errors(self):
        for code in [302,403,404]:
            with patch('urllib.request.OpenerDirector.open',side_effect=urllib.error.HTTPError('http://localhost',code,'failure',{},None)):
                self.assertIn('zbx_tor_http_status %d\n'%code,tor.collect('9035'))

    def test_invalid_port(self):
        with patch('urllib.request.OpenerDirector.open') as request:
            for port in ['0','65536','abc','9035/metrics','-1']:
                self.assertIn('zbx_tor_metrics_ok 0\n',tor.collect(port))
            request.assert_not_called()

    def test_transport_failure(self):
        with patch('urllib.request.OpenerDirector.open',side_effect=TimeoutError()):
            self.assertIn('zbx_tor_http_status 0\n',tor.collect('9035'))

class TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import yaml
        cls.export=yaml.safe_load((ROOT/'Template_Tor_Agent2.yaml').read_text())['zabbix_export']
        cls.template=cls.export['templates'][0]
        cls.normalized=tor.normalize(FIXTURE)

    def test_identity_and_references(self):
        ids=[]
        def walk(v):
            if isinstance(v,dict):
                if 'uuid' in v:ids.append(v['uuid'])
                for value in v.values():walk(value)
            elif isinstance(v,list):
                for value in v:walk(value)
        walk(self.export)
        self.assertEqual(len(ids),len(set(ids)))
        self.assertTrue(all(re.fullmatch('[a-f0-9]{32}',x) for x in ids))
        keys=[x['key'] for x in self.template['items']]
        self.assertEqual(len(keys),len(set(keys)))
        for item in self.template['items'][1:]+self.template['discovery_rules'][0]['item_prototypes']:
            self.assertIn(item['master_item']['key'],keys)

    def samples(self):
        rows=[]
        for line in self.normalized.splitlines():
            if line.startswith('#') or not line:continue
            m=re.fullmatch(r'([a-zA-Z0-9_]+)(?:\{(.*)\})?\s+([^ ]+)',line)
            self.assertIsNotNone(m,line)
            labels=dict(re.findall(r'(\w+)="([^"]*)"',m[2] or ''))
            rows.append((m[1],labels,float(m[3])))
        return rows

    def test_all_selectors_match_fixture(self):
        rows=self.samples()
        onions=sorted({labels['onion'] for _,labels,_ in rows if 'onion' in labels})
        self.assertEqual(len(onions),3)
        for item in self.template['items']+self.template['discovery_rules'][0]['item_prototypes']:
            for step in item.get('preprocessing',[]):
                if step['type']!='PROMETHEUS_PATTERN':continue
                query,mode,_=step['parameters']
                if query.startswith('zbx_tor_') and query!='zbx_tor_socket_limit':continue
                for onion in (onions if '{#ONION}' in query else ['']):
                    q=query.replace('{#ONION}',onion)
                    m=re.fullmatch(r'(\w+)(?:\{(.*)\})?',q)
                    wanted=dict(re.findall(r'(\w+)="([^"]*)"',m[2] or ''))
                    found=[v for metric,labels,v in rows if metric==m[1] and all(labels.get(k)==v for k,v in wanted.items())]
                    self.assertTrue(found,q)
                    if mode=='value':self.assertEqual(len(found),1,q)

    def test_socket_javascript(self):
        item=next(x for x in self.template['items'] if x['key']=='tor.sockets.utilization')
        js=item['preprocessing'][0]['parameters'][0]
        code='const fn=new Function("value",'+json.dumps(js)+'); process.stdout.write(String(fn('+json.dumps(self.normalized)+')));'
        result=subprocess.check_output(['node','-e',code],text=True)
        self.assertAlmostEqual(float(result),100*10/65504)
        code='const fn=new Function("value",'+json.dumps(js)+'); try { fn(""); process.exit(1); } catch(e) { process.exit(0); }'
        subprocess.run(['node','-e',code],check=True)

    def test_discovery_outage_guard(self):
        js=self.template['discovery_rules'][0]['preprocessing'][0]['parameters'][0]
        code='const fn=new Function("value",'+json.dumps(js)+'); fn("zbx_tor_metrics_ok 1\\n"); try { fn("zbx_tor_metrics_ok 0\\n"); process.exit(1); } catch(e) { process.exit(0); }'
        subprocess.run(['node','-e',code],check=True)

if __name__=='__main__':unittest.main()
