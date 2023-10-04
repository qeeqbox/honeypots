'''
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
'''

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')

from cgi import FieldStorage
from requests.packages.urllib3 import disable_warnings
from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.python import log as tlog
from random import choice
from tempfile import gettempdir, _get_candidate_names
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress

disable_warnings()


class QHTTPServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.key = path.join(gettempdir(), next(_get_candidate_names()))
        self.cert = path.join(gettempdir(), next(_get_candidate_names()))
        self.mocking_server = choice(['Apache', 'nginx', 'Microsoft-IIS/7.5', 'Microsoft-HTTPAPI/2.0', 'Apache/2.2.15', 'SmartXFilter', 'Microsoft-IIS/8.5', 'Apache/2.4.6', 'Apache-Coyote/1.1', 'Microsoft-IIS/7.0', 'Apache/2.4.18', 'AkamaiGHost', 'Apache/2.2.25', 'Microsoft-IIS/10.0', 'Apache/2.2.3', 'nginx/1.12.1', 'Apache/2.4.29', 'cloudflare', 'Apache/2.2.22'])
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 80
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def http_server_main(self):
        _q_s = self

        class MainResource(Resource):

            isLeaf = True

            home_file = b'''
<!DOCTYPE html>
<html>
   <head>
	  <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.0.0-beta.3/css/bootstrap.min.css' />
	  <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css' />
	  <meta http-equiv='content-type' content='text/html;charset=utf-8' />
	  <title>Login</title>
	  <style>
		 body,html{height: 100%;text-align: center;},
	  </style>
   </head>
   <body>
	  <div class='container-fluid h-100'>
		 <div class='row justify-content-center h-100 align-items-center'>
			<div class='col col-xl-3'>
			   <b>We'll back soon..</b>
			</div>
		 </div>
	  </div>
   </body>
</html>'''

            login_file = b'''<!DOCTYPE html>
<html>
   <head>
	  <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.0.0-beta.3/css/bootstrap.min.css' />
	  <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css' />
	  <meta http-equiv='content-type' content='text/html;charset=utf-8' />
	  <title>Login</title>
	  <style>body,html {height: 100%;}</style>
   </head>
   <body>
	  <div class='container-fluid h-100'>
		 <div class='row justify-content-center h-100 align-items-center'>
			<div class='col col-xl-3'>
			   <form id='login' action='' method='post'>
				  <div class='form-group'>
					 <input class='form-control form-control-sm' name='username' type='text' placeholder='username' id='username'>
				  </div>
				  <div class='form-group'>
					 <input class='form-control form-control-sm' name='password' type='password' placeholder='password' id='password'>
				  </div>
				  <div class='form-group'>
					 <button class='btn btn-default btn-sm btn-block' type='submit'>login</button>
				  </div>
			   </form>
			</div>
		 </div>
	  </div>
   </body>
</html>
'''

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def render(self, request):

                headers = {}
                client_ip = ""

                with suppress(Exception):
                    def check_bytes(string):
                        if isinstance(string, bytes):
                            return string.decode()
                        else:
                            return str(string)
                    for item, value in dict(request.requestHeaders.getAllRawHeaders()).items():
                        headers.update({check_bytes(item): ','.join(map(check_bytes, value))})
                    headers.update({'method': check_bytes(request.method)})
                    headers.update({'uri': check_bytes(request.uri)})

                if 'fix_get_client_ip' in _q_s.options:
                    with suppress(Exception):
                        raw_headers = dict(request.requestHeaders.getAllRawHeaders())
                        if b'X-Forwarded-For' in raw_headers:
                            client_ip = check_bytes(raw_headers[b'X-Forwarded-For'][0])
                        elif b'X-Real-IP' in raw_headers:
                            client_ip = check_bytes(raw_headers[b'X-Real-IP'][0])

                if client_ip == "":
                    client_ip = request.getClientAddress().host

                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.logs.info({'server': 'http_server', 'action': 'connection', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': headers})
                    else:
                        _q_s.logs.info({'server': 'http_server', 'action': 'connection', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                if _q_s.mocking_server != '':
                    request.responseHeaders.removeHeader('Server')
                    request.responseHeaders.addRawHeader('Server', _q_s.mocking_server)

                if request.method == b'GET' or request.method == b'POST':
                    _q_s.logs.info({'server': 'http_server', 'action': request.method.decode(), 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                if request.method == b'GET':
                    if request.uri == b'/login.html':
                        if _q_s.username != '' and _q_s.password != '':
                            request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                            return self.login_file

                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.login_file

                elif request.method == b'POST':
                    self.headers = request.getAllHeaders()
                    if request.uri == b'/login.html' or b'/':
                        if _q_s.username != '' and _q_s.password != '':
                            form = FieldStorage(fp=request.content, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers[b'content-type'], })
                            if 'username' in form and 'password' in form:
                                username = self.check_bytes(form['username'].value)
                                password = self.check_bytes(form['password'].value)
                                status = 'failed'
                                if username == _q_s.username and password == _q_s.password:
                                    username = _q_s.username
                                    password = _q_s.password
                                    status = 'success'
                                _q_s.logs.info({'server': 'http_server', 'action': 'login', 'status': status, 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'username': username, 'password': password, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.home_file
                else:
                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.home_file

        reactor.listenTCP(self.port, Site(MainResource()))
        reactor.run()

    def run_server(self, process=False, auto=False):
        status = 'error'
        run = False
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    run = True
            elif self.close_port() and self.kill_server():
                run = True

            if run:
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'http_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.http_server_main()

    def close_port(self):
        ret = close_port_wrapper('http_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('http_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from requests import get, post
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            get('http://{}:{}'.format(_ip, _port), verify=False)
            post('http://{}:{}/login.html'.format(_ip, _port), data={'username': (None, _username), 'password': (None, _password)})


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qhttpserver = QHTTPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        qhttpserver.run_server()
