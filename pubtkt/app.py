import os
import sys
import datetime
import pprint
import urllib
import time

import memcache
import cherrypy

import app
import ticket
import crowd
import pages

class LoginOK (Exception):
    '''Raised to indicate successful authentication.'''
    pass

class LoginFAIL (Exception):
    '''Raised to indicate failed authentication.'''
    pass

class FoundSSOToken (Exception):
    '''Raised during setup phase if the SSO token is found in a cookie.'''
    pass

class App (object):
    cookiename = 'seas_ac_auth'

    def __init__ (self, config):
        '''``config`` is a path to a cherrypy-style configuration
        file (which means INI style, but the values have to be valid
        Python.'''

        self.config = config

    def error(self, status, message, traceback, version):
        '''Called on unexpected errors via error_page.default'''

        return self.render('error', 
                status=status,
                message=message)

    def get_api_object(self, appname):
        '''Creates a new crowd.Crowd object using the
        configuration appropriate to the current request.'''

        try:
            appconfig = cherrypy.request.config['crowd:%s' % appname]
        except KeyError:
            raise cherrypy.HTTPError('404')

        crowd_server = cherrypy.request.config['pubtkt']['crowd_server']
        if crowd_server.endswith('/'):
            crowd_server = crowd_server[:-1]

        api = crowd.Crowd(crowd_server,
                appconfig['crowd_name'],
                appconfig['crowd_pass'],
                timeout=int(cherrypy.request.config['pubtkt']['api_timeout']),
                )

        cherrypy.request.appconfig = appconfig
        cherrypy.request.api = api

    def setup_request(self):
        '''This is called at the start of every request.  It initializes
        cherrypy.request.ctx and, if possible, initializes
        the Crowd API objects and processes authentication 
        cookies.'''

        log = self.makelogger('SETUP')
        log('Starting setup_request.')

        # random data used througout the request
        cherrypy.request.ctx = {}

        # stored in cache keyed by crowd token
        cherrypy.request.cv = {}

        cherrypy.request.mc = memcache.Client(
                cherrypy.config['pubtkt']['memcache_clients'])

        if 'appname' in cherrypy.request.params:
            appname = cherrypy.request.params['appname']
            self.get_api_object(appname)

            try:
                self.get_token_from_pubtkt()
                self.get_token_from_crowd()
                return
            except FoundSSOToken:
                pass

            # Initialize cache value
            crowd_token = cherrypy.request.ctx['crowd_token']

            ck = ('%s/%s' % (appname, crowd_token)).encode('UTF-8')
            log('Looking for cache key %s' % ck)
            cv = cherrypy.request.mc.get(ck)

            if cv is not None and self.is_trusted(cv):
                cherrypy.request.cv.update(cv)
                log('Found trusted credentials in cache.')

    def get_token_from_pubtkt(self):
        log = self.makelogger('SETUP')

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
                raise FoundSSOToken()
            except ticket.TicketError, detail:
                log('Error processing pubtkt: %s' % detail)

    def get_token_from_crowd(self):
        log = self.makelogger('SETUP')

        # Read Crowd cookie.
        res, cookie = cherrypy.request.api.request('config/cookie')
        if res == '200' and cookie['name'] in cherrypy.request.cookie:
            log('Getting crowd token from Crowd SSO cookie.')
            cherrypy.request.ctx['crowd_token'] = \
                    cherrypy.request.cookie[cookie['name']].value
            raise FoundSSOToken()

    def finish_request(self):
        '''Called at the end of request processing.  Responsible for
        storing cached credentials into the cache.'''

        log = self.makelogger('FINISH')
        log('Starting finish_request.')

        if 'crowd_token' in cherrypy.request.ctx and cherrypy.request.cv:
            crowd_token = cherrypy.request.ctx['crowd_token']
            appname = cherrypy.request.params['appname']

            ck = ('%s/%s' % (appname, crowd_token)).encode('UTF-8')
            log('Storing cached credentials in cache key %s.' % ck)
            cherrypy.request.mc.set( ck, cherrypy.request.cv)

    def is_trusted (self, cv):
        return cv.get('auth_time', 0) > (
                time.time() -
                int(cherrypy.request.config['pubtkt']['trust_timeout']))

    def login(self, appname, back=None, user=None, password=None,
            submit=None, alert=None):

        '''Attempt to authenticate a user.  This will attempt to 
        preauthenticate a user via an existing SSO token, and if
        that fails will then handle password authentication.'''

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

        return self.loginform()

    def loginform(self, alert=None):
        '''Render the login form.'''

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
        '''This is a convenience wrapper for cherrypy.request.app.log
        that returns a callable for logging a message with the given
        context.  That is::

            log = self.makelogger('PREAUTH')
            log('Hello world!')

        Is the same as::

            cherrypy.request.app.log('Hello world!',
                context='PREAUTH')

        But it will save you typing if you need to send more than
        one log message.'''
            
        def _ (*args, **kwargs):
            kwargs['context'] = context
            return cherrypy.request.app.log(*args, **kwargs)
        return _

    def authenticate(self, user, password):
        '''Authenticate a username and password against
        Crowd.'''

        if not (user or password):
            return

        log = self.makelogger('AUTHENTICATE')
        log('Trying to authenticate user %s.' % user)

        if (user and not password) or (password and not user):
            raise LoginFAIL('Missing username or password.')

        try:
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

            cherrypy.request.cv['auth_time'] = time.time()
            cherrypy.request.ctx['crowd_token'] = session['token']
            cherrypy.request.ctx['auth_user'] = user

            log('Successful authentication for user %s.' % user)
            raise LoginOK('AUTHENTICATE')
        except crowd.CrowdError, detail:
            raise LoginFAIL('Crowd API failed: %s' % detail)

    def preauth (self):
        '''Attempt to authenticate a user using an existing SSO
        token.'''

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
        '''Ensure that a Crowd SSO token is still valid.'''

        log = self.makelogger('PREAUTH')
        if not 'crowd_token' in cherrypy.request.ctx:
            return False

        crowd_token = cherrypy.request.ctx['crowd_token']
        trust_timeout = float(
                cherrypy.request.config['pubtkt']['trust_timeout'])

        # Is Crowd authentication still valid?
        try:
            res, session = cherrypy.request.api.verify_session(crowd_token)

            if res != '200':
                log('Crowd token is not valid.')
                cherrypy.request.mc.delete(crowd_token)
                return False

            log('Crowd token is valid.')
            cherrypy.request.cv['auth_time'] = time.time()
            cherrypy.request.cv['session'] = session
        except (crowd.Disabled,crowd.Timeout):
            log('Crowd timed out')
            cherrypy.request.api.disable()

            if not 'session' in cherrypy.request.cv:
                log('No credentials in cache.')
                return False

            log('Found credentials in cache.')
            session = cherrypy.request.cv['session']

        cherrypy.request.ctx['auth_user'] = session['user']['name']
        return True

    def set_cookie_and_redirect (self):
        '''Set the Pubtkt and Crowd SSO cookies.'''

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
        log = self.makelogger('PUBTKT')
        user = cherrypy.request.ctx['auth_user']

        # Get groups from Crowd.
        groups = []

        try:
            res,groups = cherrypy.request.api.request(
                    'user/group/nested', username=user)

            if res == '200':
                groups = [x['name'] for x in groups.get('groups', [])]
                cherrypy.request.cv['groups'] = groups
            else:
                log('Failed to get groups from Crowd (%s).' % res)
        except (crowd.Disabled,crowd.Timeout):
            log('Crowd timed out')
            cherrypy.request.api.disable()
            groups = cherrypy.request.cv.get('groups', [])

        log('Found groups: %s' % ' '.join(groups))

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
        try:
            cookie = cherrypy.request.api.request('config/cookie')
            cherrypy.response.cookie[cookie[1]['name']] = \
                    cherrypy.request.ctx['crowd_token']
            cherrypy.response.cookie[cookie[1]['name']]['path'] = '/'
#        cherrypy.response.cookie[cookie[1]['name']]['domain'] = \
#                cookie[1]['domain']
        except (crowd.Disabled,crowd.Timeout):
            pass

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
            cherrypy.request.mc.delete(token)
            res, data = cherrypy.request.api.request(
                    'session', path_info='/%s' % token, 
                    add_json=False, method='DELETE')
            log('Invalidated Crowd session (%s)' % res)

    def logout(self, appname, back=None):
        '''Delete all SSO cookies and invalidate the Crowd
        session.'''

        self.invalidate_crowd_session()
        self.delete_crowd_cookie()
        self.delete_pubtkt_cookie()
        return self.render('logout', back=back)

    def unauth(self, appname, back=None):
        return self.render('unauth', back=back)

    @cherrypy.tools.response_headers(headers = [('Content-Type', 'text/plain')])
    def showconfig(self):
        return pprint.pformat(cherrypy.request.config)

    def render (self, page, **params):
        '''Render a page, making sure that any macro collections
        are available.'''

        return self.pages.render(page,
                macros=['common'],
                **params)

    def default(self):
        '''Handler for "/".'''
        return self.render('default')

    def setup_routes(self):
        d = cherrypy.dispatch.RoutesDispatcher()

        d.connect('unauth', '/:appname/unauth', self.unauth)
        d.connect('login',  '/:appname/login',  self.login)
        d.connect('logout', '/:appname/logout', self.logout)

        d.connect('default', '/', self.default)

        return d

    def setup_global_config(self):

        defaults = {
                'api_timeout': 10,
                'trust_timeout': 1800,
                'templatedir': os.path.join(os.getcwd(), 'templates'),
                'staticdir': os.path.join(os.getcwd(), 'static'),
                'validuntil': 1800,
                'graceperiod': 1200,
                'memcache_clients': ['127.0.0.1:11211'],
                }

        cherrypy.config.update({'pubtkt': {}})
        cherrypy.config.update(self.config)
        for k, v in defaults.items():
            cherrypy.config['pubtkt'].setdefault(k,v)

    def setup_hooks(self):
        cherrypy.tools.setup_request = cherrypy.Tool('on_start_resource',
                self.setup_request)
        cherrypy.tools.finish_request = cherrypy.Tool('on_end_resource',
                self.finish_request)

    def mount_app(self):
        app_conf = {
            '/': {
                'request.dispatch': self.setup_routes(),
                'error_page.default': self.error,
                'tools.setup_request.on': True,
                'tools.finish_request.on': True,
                },
            '/static': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': os.path.abspath(
                    cherrypy.config['pubtkt']['staticdir']),
                },
            '/favicon.ico': {
                'tools.staticfile.on': True,
                'tools.staticfile.filename': '%s/images/favicon.ico' % (
                    os.path.abspath(cherrypy.config['pubtkt']['staticdir'])),
                },
            }

        self.app = cherrypy.tree.mount(None, config=app_conf)


    def run(self):  
        self.setup_global_config()
        self.setup_hooks()
        self.mount_app()

        self.pages = pages.Pages(
                cherrypy.config['pubtkt']['templatedir'])
        self.pubkey = cherrypy.config['pubtkt']['pubkey']
        self.privkey = cherrypy.config['pubtkt']['privkey']
        self.validuntil = datetime.timedelta(
                seconds=int(cherrypy.config['pubtkt']['validuntil']))
        self.graceperiod = datetime.timedelta(
                seconds=int(cherrypy.config['pubtkt']['graceperiod']))

        cherrypy.engine.start()
        cherrypy.engine.block()

if __name__ == '__main__':
    pass

