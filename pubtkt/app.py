import os
import sys
import datetime
import pprint

from M2Crypto import RSA
import cherrypy

import app
import ticket
import crowd
import pages

class App (object):
    cookiename = 'seas_ac_auth'

    def __init__ (self, config):
        self.config = config

    def error(self, status, message, traceback, version):
        return self.pages.render('error', macros=['common'],
                status=status, message=message)

    def login(self, app=None, back=None):
        crowdapp = cherrypy.request.config['crowd:%s' % app]

        try:
            user = cherrypy.request.headers.get('X-Remote-User',
                    crowdapp['default_user'])
        except KeyError:
            raise cherrypy.HTTPError('500',
                    'Unable to determine your username.')

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
        
        if back is not None:
            raise cherrypy.HTTPRedirect(back)
        else:
            return self.pages.render('login', macros=['common'],
                    user=user, tokens=tokens)

    def logout(self, app=None, back=None):
        cherrypy.response.cookie[self.cookiename] = ''
        cherrypy.response.cookie[self.cookiename]['expires'] = 0
        return self.pages.render('logout', macros=['common'], back=back)

    def unauth(self, app=None, back=None):
        return self.pages.render('unauth', macros=['common'], back=back)

    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def showconfig(self):
        return pprint.pformat(cherrypy.request.config)

    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def checkpw(self, app, user, password):
        crowdapp = cherrypy.request.config['crowd:%s' % app]

        api = crowd.Crowd(cherrypy.request.config['pubtkt']['crowd_server'],
                crowdapp['crowd_name'], crowdapp['crowd_pass']
                )

        return pprint.pformat(api.authenticate(user, password))

    def setup_routes(self):
        d = cherrypy.dispatch.RoutesDispatcher()

        d.connect('config', '/dump',        self.showconfig)
        d.connect('checkpw', '/:app/checkpw/:user/:password',        self.checkpw)
        d.connect('logout', '/logout',      self.logout)
        d.connect('unauth', '/unauth',      self.unauth)

        d.connect('login',  '/:app/login',  self.login)

        return d

    def run(self):
        cherrypy.config.update(self.config)

        global_conf = {
            '/': {
                'request.dispatch': self.setup_routes(),
                'error_page.default': self.error,
                'tools.staticdir.root': os.getcwd(),
                },
            '/static': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': 'static'
                }
            }

        app = cherrypy.tree.mount(None, config=global_conf)

        self.pages = pages.Pages(
                cherrypy.config['pubtkt']['templatedir'])
        self.privkey = RSA.load_key(
                cherrypy.config['pubtkt']['privkey'])
        self.validuntil = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['validuntil']))
        self.graceperiod = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['graceperiod']))
 
        cherrypy.engine.start()
        cherrypy.engine.block()

