import os
import sys
import datetime
import pprint
import urllib
import time
import logging

import memcache
import cherrypy

import app
import ticket
import crowd
import pages

# CACHEVERSION is prepended to cache keys.  This lets us 
# invalidate the cache (e.g., in the event of an incompatible
# change in the format of cached data) by simply incrementing
# CACHEVERSION.
CACHEVERSION=2

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

    def __init__ (self, config, debug=False):
        '''``config`` is a path to a cherrypy-style configuration
        file (which means INI style, but the values have to be valid
        Python.'''

        self.config = config
        self.debug = debug

    def error(self, status, message, traceback, version):
        '''Called on unexpected errors via error_page.default'''

        return self.render('error', 
                status=status,
                message=message)

    def get_api_object(self, appname):
        '''Creates a new ``crowd.RESTClient`` object using the
        configuration appropriate to the current request.'''

        conf = cherrypy.request.config['pubtkt']

        try:
            appconf = cherrypy.request.config['crowd:%s' % appname]
        except KeyError:
            raise cherrypy.HTTPError('404',
                    'Cannot find the requested application.')

        crowd_server = conf['crowd_server']
        if crowd_server.endswith('/'):
            crowd_server = crowd_server[:-1]

        apitimeout = int(conf['api_timeout'])
        api = crowd.RESTClient(
                crowd_server,
                (appconf['crowd_name'], appconf['crowd_pass']),
                apitimeout=int(conf['api_timeout']),
                cacheclients=conf['memcache_clients'],
                )

        cherrypy.request.appconf = appconf
        cherrypy.request.api = api

    def cachekey(self):
        ctx = cherrypy.request.ctx

        token = ctx['crowd_token']
        appname = ctx['appname']
        key = ('%s:%s:%s' % (CACHEVERSION, appname, token)).encode('UTF-8')
        print 'KEY:', key
        return key

    def store(self):
        cherrypy.request.app.log('Storing credentials in cache.',
                context='SETUP')
        conf = cherrypy.request.config['pubtkt']
        timeout = int(conf['trust_timeout'])

        try:
            key = self.cachekey()
            cherrypy.request.cache.set(key, cherrypy.request.cv,
                    time = timeout)
        except KeyError:
            pass

    def fetch(self):
        cherrypy.request.app.log('Looking for credentials in cache.',
                context='SETUP')
        try:
            key = self.cachekey()
            val = cherrypy.request.cache.get(key)
            if val is not None:
                cherrypy.request.app.log('Found credentials in cache.',
                        context='SETUP')
        except KeyError:
            cherrypy.request.app.log('No credentials in cache.',
                    context='SETUP')

        if val is None:
            val = {}

        cherrypy.request.cv = val

    def setup_cache(self):
        conf = cherrypy.request.config['pubtkt']
        cherrypy.request.cache = memcache.Client(conf['memcache_clients'])
        cherrypy.request.cv = {}

    def setup_request(self):
        '''This is called at the start of every request.'''

        if self.debug:
            cherrypy.request.app.log.error_log.setLevel(logging.DEBUG)

        log = self.makelogger('SETUP')
        log('Starting setup_request.')

        self.setup_cache()

        ctx = cherrypy.request.ctx = {}
        if not 'appname' in cherrypy.request.params:
            log('No appname in request.')
            return
        ctx['appname'] = cherrypy.request.params['appname']

        self.get_api_object(cherrypy.request.params['appname'])

        # Read Crowd cookie configuration.
        cookie = cherrypy.request.api.config.cookie()
        ctx['crowd_cookie_name'] = cookie['name']

        try:
            self.get_token_from_pubtkt()
            self.get_token_from_crowd()
            return
        except FoundSSOToken:
            pass

        self.fetch()

    def get_token_from_pubtkt(self):
        log = self.makelogger('SETUP')
        ctx = cherrypy.request.ctx

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
                ctx['pubtkt'] = pubtkt
                ctx['crowd_token'] = pubtkt['udata']
                raise FoundSSOToken()
            except ticket.TicketError, detail:
                log('Error processing pubtkt: %s' % detail)

    def get_token_from_crowd(self):
        log = self.makelogger('SETUP')
        ctx = cherrypy.request.ctx

        if ctx['crowd_cookie_name'] in cherrypy.request.cookie:
            log('Getting crowd token from Crowd SSO cookie.')
            ctx['crowd_token'] = \
                    cherrypy.request.cookie[ctx['crowd_cookie_name']].value
            raise FoundSSOToken()

    def finish_request(self):
        '''Called at the end of request processing.  Responsible for
        storing cached credentials into the cache.'''

        log = self.makelogger('FINISH')
        log('Starting finish_request.')

        if not 'appname' in cherrypy.request.params:
            log('No appname in request.')
            return

        ctx = cherrypy.request.ctx
        conf = cherrypy.request.config['pubtkt']

        self.store()

    def login(self, appname, back=None, user=None, password=None,
            submit=None, alert=None):

        '''Attempt to authenticate a user.  This will attempt to 
        preauthenticate a user via an existing SSO token, and if
        that fails will then handle password authentication.'''

        log = self.makelogger('LOGIN')
        log('Login request to %s by %s.' % (appname, user or 'unknown'),
                severity=logging.INFO)

        try:
            self.preauth()
            self.authenticate(user, password)
        except LoginOK, detail:
            log('Login okay: %s via %s' %
                    (cherrypy.request.ctx['auth_user'], detail),
                    severity=logging.INFO)
            return self.set_cookie_and_redirect()
        except LoginFAIL, detail:
            log('Login failed: %s' % detail, 
                    severity=logging.WARNING)
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
                appname=cherrypy.request.appconf.get('name'),
                params=cherrypy.request.params,
                request=cherrypy.request)

    def makelogger(self, context, severity=logging.DEBUG):
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
            if severity is not None:
                kwargs.setdefault('severity', severity)
            return cherrypy.request.app.log(*args, **kwargs)

        return _

    def authenticate(self, user, password):
        '''Authenticate a username and password against
        Crowd.'''

        if not (user or password):
            return

        log = self.makelogger('AUTHENTICATE')
        ctx = cherrypy.request.ctx
        cv = cherrypy.request.cv
        conf = cherrypy.request.config['pubtkt']
        log('Trying to authenticate user %s.' % user)

        if (user and not password) or (password and not user):
            raise LoginFAIL('Missing username or password.')

        try:
            userinfo = cherrypy.request.api.authenticate(user, password)
            log('Good password for user %s.' % user)

            if not userinfo['active']:
                raise LoginFAIL('User %s is not active.' % user)

            log('User %s is active.' % user)

            # Get session token from Crowd.
            session = cherrypy.request.api.session.post(
                    body={'username': user, 'password': password})

            cv['userinfo'] = userinfo
            cv['session'] = session
            ctx['crowd_token'] = session['token']
            ctx['auth_user'] = user

            log('Successful authentication for user %s.' % user)
            raise LoginOK('AUTHENTICATE')
        except crowd.RESTError, detail:
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
        ctx = cherrypy.request.ctx
        conf = cherrypy.request.config['pubtkt']

        if not 'crowd_token' in ctx:
            return False

        crowd_token = ctx['crowd_token']
        log('Crowd token: %s' % crowd_token)

        # Is Crowd authentication still valid?
        try:
            session = cherrypy.request.api.session.post('/%s' % crowd_token)

            log('Crowd token is valid.')
            cherrypy.request.cv['session'] = session
        except crowd.HTTPError, detail:
            log('Crowd token is not valid (%s)' % detail)
            return False
        except (crowd.Disabled,crowd.Timeout):
            log('Crowd timed out', severity=logging.ERROR)
            cherrypy.request.api.disable()

            if not 'session' in cherrypy.request.cv:
                log('No credentials in cache.')
                return False

            log('Found credentials in cache.')
            session = cherrypy.request.cv['session']

        ctx['auth_user'] = session['user']['name']
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
            groups = cherrypy.request.api.user.group.nested(
                    username=user)

            groups = [x['name'] for x in groups.get('groups', [])]
            cherrypy.request.cv['groups'] = groups
        except crowd.HTTPError, detail:
            log('Failed to get groups from Crowd (%s).' % detail)
        except (crowd.Disabled,crowd.Timeout):
            log('Crowd timed out', severity=logging.ERROR)
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
        ctx = cherrypy.request.ctx

        try:
            cherrypy.response.cookie[ctx['crowd_cookie_name']] = \
                    ctx['crowd_token']
            cherrypy.response.cookie[ctx['crowd_cookie_name']]['path'] = '/'
#        cherrypy.response.cookie[ctx['crowd_cookie_name']]['domain'] = \
#                cookie['domain']
        except (crowd.Disabled,crowd.Timeout):
            pass

    def delete_crowd_cookie(self):
        ctx = cherrypy.request.ctx

        cherrypy.response.cookie[ctx['crowd_cookie_name']] = ''
        cherrypy.response.cookie[ctx['crowd_cookie_name']]['path'] = '/'
        cherrypy.response.cookie[ctx['crowd_cookie_name']]['expires'] = 0
#        cherrypy.response.cookie[cookie['name']]['domain'] = \
#                cookie['domain']

    def invalidate_crowd_session(self):
        log = self.makelogger('LOGOUT')
        ctx = cherrypy.request.ctx

        if 'crowd_token' in ctx:
            ck = self.cachekey()
            cherrypy.request.mc.delete(ck)
            try:
                session = cherrypy.request.api.session.delete(
                        '/%s' % ctx['crowd_token'])
            except crowd.RESTError, detail:
                log('Error expiring session: %s' % detail)

            log('Invalidated Crowd session.')

    def logout(self, appname, back=None):
        '''Delete all SSO cookies and invalidate the Crowd
        session.'''

        self.invalidate_crowd_session()
        self.delete_cached_credentials()
        self.delete_crowd_cookie()
        self.delete_pubtkt_cookie()
        return self.render('logout', back=back)

    def delete_cached_credentials(self):
        ck = self.cachekey()
        if ck:
            cherrypy.request.mc.delete(ck)
            cherrypy.request.cv = None

    def unauth(self, appname, back=None):
        return self.render('unauth', back=back)

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

        if cherrypy.config['pubtkt'].get('debug', 'no').lower() == 'yes':
            self.debug = True

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

