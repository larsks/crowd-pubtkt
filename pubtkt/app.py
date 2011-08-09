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
    def login(self, back, unauth=False, timeout=False):
        tkt = pubtkt.ticket.Ticket(self.privkey, uid='lars',
                validuntil = self.validuntil,
                graceperiod = self.graceperiod)

        cherrypy.response.cookie[self.cookiename] = str(tkt)
        
        raise cherrypy.HTTPRedirect(back)

    @cherrypy.expose
    def logout(self):
        cherrypy.response.cookie[self.cookiename] = ''
        cherrypy.response.cookie[self.cookiename]['expires'] = 0
        return 'logout'

    @cherrypy.expose
    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def showconfig(self):
        return pprint.pformat(cherrypy.request.app.config)

    def run(self):
        app = cherrypy.tree.mount(self, '/', self.config)

        self.privkey = RSA.load_key(app.config['pubtkt']['privkey'])
        self.validuntil = datetime.timedelta(
                minutes=int(app.config['pubtkt']['validuntil']))
        self.graceperiod = datetime.timedelta(
                minutes=int(app.config['pubtkt']['graceperiod']))
 
        cherrypy.server.quickstart()
        cherrypy.engine.start()

