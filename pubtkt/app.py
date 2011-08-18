import os
import sys
import datetime
import pprint
import urllib
import time

import cherrypy

import app
import ticket
import crowd
import pages

class LoginOK (Exception):
    pass

class LoginFAIL (Exception):
    pass

class App (object):
    cookiename = 'seas_ac_auth'

    def __init__ (self, config):
        self.config = config

    def error(self, status, message, traceback, version):
        return self.render('error', 
                status=status, message=message)

    def get_api_object(self, appname):
        '''Creates a new crowd.Crowd object using the
        configuration appropriate to the current request.'''

        appconfig = cherrypy.request.config['crowd:%s' % appname]

        crowd_server = cherrypy.request.config['pubtkt']['crowd_server']
        if crowd_server.endswith('/'):
            crowd_server = crowd_server[:-1]

        api = crowd.Crowd(crowd_server,
                appconfig['crowd_name'], appconfig['crowd_pass']
                )

        cherrypy.request.appconfig = appconfig
        cherrypy.request.api = api

    def setup_request(self):
        cherrypy.request.ctx = {}

        if 'appname' in cherrypy.request.params:
            self.get_api_object(cherrypy.request.params['appname'])

    def login(self, appname, back=None, user=None, password=None,
            submit=None, alert=None):

        log = self.makelogger('LOGIN')
        log('Login request to %s by %s.' % (appname, user))

        try:
            self.preauth()
            self.authenticate(user, password)
        except LoginOK:
            return self.set_cookie_and_redirect()
        except LoginFAIL:
            return self.loginform('Bad username or password.')

        return self.loginform()

    def loginform(self, alert=None):
        if not cherrypy.request.params.get('user'):
            if 'pubtkt' in cherrypy.request.ctx:
                user = cherrypy.request.ctx['pubtkt']['uid']
                cherrypy.request.params['user'] = user

        return self.render('login',
                alert=alert,
                appname=cherrypy.request.appconfig['name'],
                params=cherrypy.request.params,
                request=cherrypy.request)

    def makelogger(self, context):
        def _ (*args, **kwargs):
            kwargs['context'] = context
            return cherrypy.request.app.log(*args, **kwargs)
        return _

    def authenticate(self, user, password):
        if (user and not password) or (password and not user):
            raise LoginFAIL()

        log = self.makelogger('AUTHENTICATE')
        log('Trying to authenticate user %s.' % user)

        res, userinfo = cherrypy.request.api.authenticate(user, password)

        if res != '200':
            log('Authentication via Crowd failed for %s.' % user)
            raise LoginFAIL()

        log('Good password for user %s.' % user)

        if not userinfo['active']:
            log('User %s is not active.' % user)
            raise LoginFAIL()

        log('User %s is active.' % user)

        # Get session token from Crowd.
        res, session = cherrypy.request.api.create_session(
                user, password)

        if res != '201':
            log('Failed to create new session for user %s.' % user)
            raise LoginFAIL()

        cherrypy.request.crowd_token = session['token']
        cherrypy.request.crowd_user = user

        log('Successful authentication for user %s.' % user)
        raise LoginOK('AUTHENTICATE')

    def preauth (self):
        log = self.makelogger('PREAUTH')
        log('Starting preauth.')

        if self.verify_pubtkt_cookie():
            if self.verify_crowd_token():
                raise LoginOK('PREAUTH')

        log('Could not preauthenticate request.')
        return False

    def verify_pubtkt_cookie(self):
        log = self.makelogger('PREAUTH')
        if not self.cookiename in cherrypy.request.cookie:
            return False

        log('Found pubtkt cookie.')

        cookie = cherrypy.request.cookie[self.cookiename]

        try:
            # Is pubtkt token still valid?
            pubtkt = ticket.Ticket(
                    urllib.unquote(cookie.value))

            # save pubtkt in case we want to refer to it later
            cherrypy.request.ctx['pubtkt'] = pubtkt

            # Check signature (ticket.BadSignatureError on failure)
            pubtkt.verify(self.pubkey)
            log('Verified signature on pubtkt cookie.')

            # Has ticket expired?
            if pubtkt['validuntil'] < time.time():
                log('Pubtkt cookie has expired.')
                return False

            cherrypy.request.ctx['pubtkt_valid'] = True
            log('Pubtkt cookie is active.')

            return True
        except ticket.TicketError:
            pass

        return False

    def verify_crowd_token(self):
        log = self.makelogger('PREAUTH')

        # Is Crowd authentication still valid?
        crowd_token = cherrypy.request.ctx['pubtkt']['udata']
        res, data = cherrypy.request.api.verify_session(crowd_token)

        if res != '200':
            log('Crowd token is not valid.')
            return False

        log('Crowd token is valid.')
        cherrypy.request.ctx['crowd_token'] = crowd_token
        return True

    def set_cookie_and_redirect (self):

        self.set_pubtkt_cookie()
        self.set_crowd_cookie()

        back = cherrypy.request.params.get('back')
        if back:
            raise cherrypy.HTTPRedirect(back)
        else:
            return self.render('loginok',
                    user=cherrypy.request.crowd_user,
                    params=cherrypy.request.params,
                    request=cherrypy.request)

    def set_pubtkt_cookie(self):
        user = cherrypy.request.ctx['crowd_user']

        # Get groups from Crowd.
        res,groups = cherrypy.request.api.request(
                'user/group/nested', username=user)
        groups = [x['name'] for x in groups.get('groups', [])]

        tkt = ticket.Ticket(uid=user,
                validuntil = self.validuntil,
                tokens = groups,
                udata = cherrypy.request.crowd_token,
                graceperiod = self.graceperiod)

        tkt.sign(self.privkey)

        cherrypy.response.cookie[self.cookiename] = urllib.quote(
                tkt.to_string(sig=True))
        cherrypy.response.cookie[self.cookiename]['path'] = '/'

    def delete_pubtkt_cookie(self):
        cherrypy.response.cookie[self.cookiename] = ''
        cherrypy.response.cookie[self.cookiename]['path'] = '/'
        cherrypy.response.cookie[self.cookiename]['expires'] = 0

    def set_crowd_cookie(self):
        cookie = cherrypy.request.api.request('config/cookie')
        cherrypy.response.cookie[cookie[1]['name']] = cherrypy.request.crowd_token
        cherrypy.response.cookie[cookie[1]['name']]['path'] = '/'
#        cherrypy.response.cookie[cookie[1]['name']]['domain'] = \
#                cookie[1]['domain']

    def delete_crowd_cookie(self):
        cookie = cherrypy.request.api.request('config/cookie')
        cherrypy.response.cookie[cookie[1]['name']] = ''
        cherrypy.response.cookie[cookie[1]['name']]['path'] = '/'
        cherrypy.response.cookie[cookie[1]['name']]['expires'] = 0
#        cherrypy.response.cookie[cookie[1]['name']]['domain'] = \
#                cookie[1]['domain']

    def logout(self, appname, back=None):
        self.delete_crowd_cookie()
        self.delete_pubtkt_cookie()
        return self.render('logout', back=back)

    def unauth(self, appname, back=None):
        return self.render('unauth', back=back)

    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def showconfig(self):
        return pprint.pformat(cherrypy.request.config)

    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def checkpw(self, appname, user, password):
        crowdapp = cherrypy.request.config['crowd:%s' % appname]

        return pprint.pformat(api.authenticate(user, password))

    def render (self, page, **params):
        return self.pages.render(page,
                macros=['common'],
                **params)

    def setup_routes(self):
        d = cherrypy.dispatch.RoutesDispatcher()

        d.connect('config', '/dump',        self.showconfig)

        d.connect('unauth', '/:appname/unauth', self.unauth)
        d.connect('login',  '/:appname/login',  self.login)
        d.connect('logout', '/:appname/logout', self.logout)

        return d

    def run(self):
        cherrypy.config.update(self.config)
        cherrypy.tools.setup_request = cherrypy.Tool('on_start_resource',
                self.setup_request)

        global_conf = {
            '/': {
                'request.dispatch': self.setup_routes(),
                'error_page.default': self.error,
                'tools.staticdir.root': os.getcwd(),
                'tools.staticfile.root': os.getcwd(),
                'tools.setup_request.on': True,
                },
            '/static': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': 'static'
                },
            '/favicon.ico': {
                'tools.staticfile.on': True,
                'tools.staticfile.filename': 'static/images/favicon.ico'
                },
            }

        self.app = cherrypy.tree.mount(None, config=global_conf)

        self.pages = pages.Pages(
                cherrypy.config['pubtkt']['templatedir'])
        self.pubkey = cherrypy.config['pubtkt']['pubkey']
        self.privkey = cherrypy.config['pubtkt']['privkey']
        self.validuntil = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['validuntil']))
        self.graceperiod = datetime.timedelta(
                minutes=int(cherrypy.config['pubtkt']['graceperiod']))

        cherrypy.engine.start()
        cherrypy.engine.block()

