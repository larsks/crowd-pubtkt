import os
import sys
import datetime
import pprint
import urllib
import time

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

    def get_api_object(self, crowdapp):
        crowd_server = cherrypy.request.config['pubtkt']['crowd_server']
        if crowd_server.endswith('/'):
            crowd_server = crowd_server[:-1]

        api = crowd.Crowd(crowd_server,
                crowdapp['crowd_name'], crowdapp['crowd_pass']
                )

        return api

    def login(self, app=None, back=None):
        cherrypy.request.crowdapp = cherrypy.request.config['crowd:%s' % app]
        cherrypy.request.crowdapi = self.get_api_object(crowdapp)

        # Is there a pubtkt cookie?
        if self.preauth():
            return self.set_cookie_and_redirect()

    def preauth (self):
        if self.cookiename in cherrypy.request.cookie:
            cookie = cherrypy.request.cookie[self.cookiename]

            try:
                # Is pubtkt token still valid?
                pubtkt = ticket.Ticket(
                        urllib.unquote(cookie.value))
                cherrypy.request.pubtkt = pubtkt

                # Check signature (ticket.BadSignatureError on failure)
                pubtkt.verify(self.pubkey)

                # Has ticket expired?
                if pubtkt['validuntil'] < time.time():
                    return False

                # Is Crowd authentication still valid?
                crowd_token = pubtkt['userdata']
            except ticket.TicketError:
                pass

        return False

    def set_cookie_and_redirect (self):
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
        api = self.get_api_object(crowdapp)

        return pprint.pformat(api.authenticate(user, password))

    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def session(self, app, user, password):
        crowdapp = cherrypy.request.config['crowd:%s' % app]
        api = self.get_api_object(crowdapp)

        tok = api.request('session',
            postdata={
                'username': user,
                'password': password,
                'validation-factors': {
                    'validationFactors': [ {
                    'name': 'remote_address',
                    'value': '10.243.18.22',
                    } ]
                    }
                },
            **{'validate-password': 'false'}
            )

        cookie = api.request('config/cookie')

        cherrypy.response.cookie[cookie[1]['name']] = tok[1]['token']
        cherrypy.response.cookie[cookie[1]['name']]['path'] = '/'
        cherrypy.response.cookie[cookie[1]['name']]['domain'] = \
                cookie[1]['domain']

        return '\n'.join([
                pprint.pformat(tok),
                pprint.pformat(cookie)
                ])

    def render (self, page, **params):
        return self.pages.render(page, macros=['common'], **params)

    def setup_routes(self):
        d = cherrypy.dispatch.RoutesDispatcher()

        d.connect('config', '/dump',        self.showconfig)
        d.connect('checkpw', '/:app/checkpw/:user/:password',
                                            self.checkpw)
        d.connect('session', '/:app/session/:user/:password',
                                            self.session)
        d.connect('render', '/render/:page', self.render)

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
        self.pubkey = RSA.load_pub_key(
                cherrypy.config['pubtkt']['pubkey'])
        self.privkey = RSA.load_key(
                cherrypy.config['pubtkt']['privkey'])
        self.validuntil = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['validuntil']))
        self.graceperiod = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['graceperiod']))
 
        cherrypy.engine.start()
        cherrypy.engine.block()

