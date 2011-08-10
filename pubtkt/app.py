import datetime
import pprint
from M2Crypto import RSA
import cherrypy

import pubtkt.app
import pubtkt.ticket

class App (object):
    cookiename = 'seas_ac_auth'

    def __init__ (self, config):
        self.config = config

    @cherrypy.expose
    def index(self):
        return 'index'

    @cherrypy.expose
    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def login(self, app=None, back=None):
        tkt = pubtkt.ticket.Ticket(self.privkey, uid='lars',
                validuntil = self.validuntil,
                graceperiod = self.graceperiod)

        cherrypy.response.cookie[self.cookiename] = str(tkt)
        
        #raise cherrypy.HTTPRedirect(back)
        text = ['app=%s' % app]
        for k,v in cherrypy.request.headers.items():
            text.append('%s=%s' % (k,v))

        return '\n'.join(text)

        return 'login to %s as %s' % (app, cherrypy.request.headers['X-Remote-User'])

    @cherrypy.expose
    def logout(self, app=None):
        cherrypy.response.cookie[self.cookiename] = ''
        cherrypy.response.cookie[self.cookiename]['expires'] = 0
        return 'logout %s' % app

    @cherrypy.expose
    def unauth(self, app=None):
        return 'unauth %s' % app

    @cherrypy.expose
    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def showconfig(self):
        return pprint.pformat(cherrypy.request.app.config)

    def setup_routes(self):
        d = cherrypy.dispatch.RoutesDispatcher()

        d.connect('config', '/showconfig', self.showconfig)

        d.connect('login', '/:app/login', self.login)
        d.connect('logout', '/:app/logout', self.logout)
        d.connect('unauth', '/:app/unauth', self.unauth)

        d.connect('main', '/:action', self)

        return d

    def run(self):
        cherrypy.config.update(self.config)

        global_conf = {
            '/': {
                'request.dispatch': self.setup_routes()
                }}

        app = cherrypy.tree.mount(None, config=global_conf)

        self.privkey = RSA.load_key(cherrypy.config['pubtkt']['privkey'])
        self.validuntil = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['validuntil']))
        self.graceperiod = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['graceperiod']))
 
        cherrypy.engine.start()
        cherrypy.engine.block()

