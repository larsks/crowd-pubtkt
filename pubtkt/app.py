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

class LoginPASS (Exception):
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
        '''This is called at the start of every request.  It initializes
        cherrypy.request.ctx and, if possible, initializes
        the Crowd API objects.'''

        log = self.makelogger('SETUP')

        cherrypy.request.ctx = {}

        if 'appname' in cherrypy.request.params:
            self.get_api_object(cherrypy.request.params['appname'])

            # Read pubtkt cookie (and extract crowd token).
            # TODO: Do we care?  Not sure.
            if self.cookiename in cherrypy.request.cookie:
                cookie = cherrypy.request.cookie[self.cookiename]

                try:
                    # Is pubtkt token still valid?
                    pubtkt = ticket.Ticket(
                            urllib.unquote(cookie.value))
                    pubtkt.verify(self.pubkey)
                    log('Verified signature on pubtkt cookie.')
                    log('Getting crowd token from pubtkt cookie.')
                    cherrypy.request.ctx['pubtkt'] = pubtkt
                    cherrypy.request.ctx['crowd_token'] = pubtkt['udata']
                    return
                except ticket.TicketError:
                    pass

            # Read Crowd cookie.
            res, cookie = cherrypy.request.api.request('config/cookie')
            if res == '200' and cookie['name'] in cherrypy.request.cookie:
                log('Getting crowd token from Crowd SSO cookie.')
                cherrypy.request.ctx['crowd_token'] = \
                        cherrypy.request.cookie[cookie['name']].value

    def login(self, appname, back=None, user=None, password=None,
            submit=None, alert=None):

        log = self.makelogger('LOGIN')
        log('Login request to %s by %s.' % (appname, user or 'unknown'))

        try:
            self.preauth()
            self.authenticate(user, password)
        except LoginOK, detail:
            log('Login okay: %s via %s' %
                    (cherrypy.request.ctx['auth_user'], detail))
            return self.set_cookie_and_redirect()
        except LoginFAIL, detail:
            log('Login failed: %s' % detail)
            return self.loginform('Bad username or password.')
        except LoginPASS:
            pass

        return self.loginform()

    def loginform(self, alert=None):
        if not cherrypy.request.params.get('user'):
            if 'pubtkt' in cherrypy.request.ctx:
                user = cherrypy.request.ctx['pubtkt']['uid']
                cherrypy.request.params['user'] = user

        return self.render('login',
                alert=alert,
                appname=cherrypy.request.appconfig.get('name'),
                params=cherrypy.request.params,
                request=cherrypy.request)

    def makelogger(self, context):
        def _ (*args, **kwargs):
            kwargs['context'] = context
            return cherrypy.request.app.log(*args, **kwargs)
        return _

    def authenticate(self, user, password):
        if not (user or password):
            return

        log = self.makelogger('AUTHENTICATE')
        log('Trying to authenticate user %s.' % user)

        if (user and not password) or (password and not user):
            raise LoginFAIL('Missing username or password.')

        res, userinfo = cherrypy.request.api.authenticate(user, password)

        if res != '200':
            raise LoginFAIL('Crowd authentication failed.')

        log('Good password for user %s.' % user)

        if not userinfo['active']:
            raise LoginFAIL('User %s is not active.' % user)

        log('User %s is active.' % user)

        # Get session token from Crowd.
        res, session = cherrypy.request.api.create_session(
                user, password)

        if res != '201':
            raise LoginFAIL('Failed to create new session for %s.' % user)

        cherrypy.request.ctx['crowd_token'] = session['token']
        cherrypy.request.ctx['auth_user'] = user

        log('Successful authentication for user %s.' % user)
        raise LoginOK('AUTHENTICATE')

    def preauth (self):
        log = self.makelogger('PREAUTH')
        log('Starting preauth.')

        if self.verify_crowd_token():
            raise LoginOK('PREAUTH (crowd)')

        log('Could not preauthenticate request.')

    def verify_pubtkt_cookie(self):
        log = self.makelogger('PREAUTH')
        if not 'pubtkt' in cherrypy.request.ctx:
            return False

        pubtkt = cherrypy.request.ctx['pubtkt']
        log('Found pubtkt cookie for user %(uid)s.' % pubtkt)

        # Has ticket expired?
        if pubtkt['validuntil'] < time.time():
            log('Pubtkt cookie has expired.')
            return False

        log('Pubtkt cookie is active.')
        return True

    def verify_crowd_token(self):
        log = self.makelogger('PREAUTH')
        if not 'crowd_token' in cherrypy.request.ctx:
            return False

        # Is Crowd authentication still valid?
        res, data = cherrypy.request.api.verify_session(
                cherrypy.request.ctx['crowd_token'])

        if res != '200':
            log('Crowd token is not valid.')
            return False

        log('Crowd token is valid.')
        cherrypy.request.ctx['auth_user'] = data['user']['name']
        return True

    def set_cookie_and_redirect (self):

        self.set_pubtkt_cookie()
        self.set_crowd_cookie()

        back = cherrypy.request.params.get('back')
        if back:
            raise cherrypy.HTTPRedirect(back)
        else:
            return self.render('loginok',
                    user=cherrypy.request.ctx['auth_user'],
                    params=cherrypy.request.params,
                    request=cherrypy.request)

    def set_pubtkt_cookie(self):
        user = cherrypy.request.ctx['auth_user']

        # Get groups from Crowd.
        res,groups = cherrypy.request.api.request(
                'user/group/nested', username=user)
        groups = [x['name'] for x in groups.get('groups', [])]

        tkt = ticket.Ticket(uid=user,
                validuntil = self.validuntil,
                tokens = groups,
                udata = cherrypy.request.ctx['crowd_token'],
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
        cherrypy.response.cookie[cookie[1]['name']] = \
                cherrypy.request.ctx['crowd_token']
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

    def invalidate_crowd_session(self):
        log = self.makelogger('LOGOUT')

        if 'crowd_token' in cherrypy.request.ctx:
            token = cherrypy.request.ctx['crowd_token']
            res, data = cherrypy.request.api.request(
                    'session', path_info='/%s' % token, 
                    add_json=False, method='DELETE')
            log('Invalidated Crowd session (%s)' % res)

    def logout(self, appname, back=None):
        self.invalidate_crowd_session()
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

