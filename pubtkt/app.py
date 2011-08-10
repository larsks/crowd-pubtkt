import os
import sys
import datetime
import pprint
from StringIO import StringIO

from M2Crypto import RSA
from simpletal import simpleTAL, simpleTALES
import cherrypy

import app
import ticket
import crowd

class App (object):
    cookiename = 'seas_ac_auth'

    def __init__ (self, config):
        self.config = config

    def render(self, page, **ctx):
        path = os.path.join(
                cherrypy.request.config['pubtkt']['templatedir'],
                '%s.html' % page)

        tales = simpleTALES.Context()
        for k,v in ctx.items():
            tales.addGlobal(k,v)

        templ = simpleTAL.compileHTMLTemplate(open(path))
        text = StringIO()
        templ.expand(tales, text)
        return text.getvalue()

    def error500(self, status, message, traceback, version):
        return self.render('error500', status=status, message=message)

    def error404(self, status, message, traceback, version):
        return self.render('error404', status=status, message=message)

    def login(self, app=None, back=None):
        user = cherrypy.request.headers['X-Remote-User']

        crowdapp = cherrypy.request.config['crowd:%s' % app]
        api = crowd.Crowd(cherrypy.request.config['pubtkt']['crowd_server'],
                crowdapp['crowd_name'], crowdapp['crowd_pass']
                )
        resp,groups = api.request('user/group/nested', username=user)

        tokens = [x['name'] for x in groups.get('groups', [])]

        tkt = ticket.Ticket(self.privkey, uid=user,
                validuntil = self.validuntil,
                tokens = tokens,
                graceperiod = self.graceperiod)

        cherrypy.response.cookie[self.cookiename] = str(tkt)
        
        raise cherrypy.HTTPRedirect(back)

    def logout(self, app=None, back=None):
        cherrypy.response.cookie[self.cookiename] = ''
        cherrypy.response.cookie[self.cookiename]['expires'] = 0
        return self.render('logout', back=back)

    def unauth(self, app=None, back=None):
        return self.render('unauth', back=back)

    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def showconfig(self):
        return pprint.pformat(cherrypy.request.config)

    def setup_routes(self):
        d = cherrypy.dispatch.RoutesDispatcher()

        d.connect('config', '/dump',        self.showconfig)
        d.connect('logout', '/logout',      self.logout)
        d.connect('unauth', '/unauth',      self.unauth)

        d.connect('login',  '/:app/login',  self.login)

        return d

    def run(self):
        cherrypy.config.update(self.config)

        global_conf = {
            '/': {
                'request.dispatch': self.setup_routes(),
                'error_page.default': self.error500,
                'error_page.404': self.error404,
                }}

        app = cherrypy.tree.mount(None, config=global_conf)

        self.privkey = RSA.load_key(cherrypy.config['pubtkt']['privkey'])
        self.validuntil = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['validuntil']))
        self.graceperiod = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['graceperiod']))
 
        cherrypy.engine.start()
        cherrypy.engine.block()

