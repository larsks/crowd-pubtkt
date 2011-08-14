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

    def get_api_object(self, app):
        '''Creates a new crowd.Crowd object using the
        configuration appropriate to the current request.'''

        crowdapp = cherrypy.request.config['crowd:%s' % app]

        crowd_server = cherrypy.request.config['pubtkt']['crowd_server']
        if crowd_server.endswith('/'):
            crowd_server = crowd_server[:-1]

        api = crowd.Crowd(crowd_server,
                crowdapp['crowd_name'], crowdapp['crowd_pass']
                )

        return api

    def login(self, app, back=None, user=None, password=None,
            submit=None, alert=None):

        cherrypy.request.crowdapi = self.get_api_object(app)

        if self.preauth():
            return self.set_cookie_and_redirect()

        # If we have both 
        if user and password:
            if self.authenticate(user, password):
                return self.set_cookie_and_redirect()
            else:
                alert = 'Incorrect username or password.'
        elif user or password or submit:
            alert = 'You must specify both a username and password.'

        return self.loginform(alert=alert)

    def loginform(self, alert=None):
        return self.pages.render('login',
                macros=['common'],
                alert=alert,
                params=cherrypy.request.params,
                request=cherrypy.request)

    def authenticate(self, user, password):
        res, userinfo = cherrypy.request.crowdapi.authenticate(user, password)

        print 'AUTHENTICATE', user, res

        if res != '200':
            return False

        print 'AUTHENTICATE', 'good password'

        if not userinfo['active']:
            return False

        print 'AUTHENTICATE', 'user active'

        # Get session token from Crowd.
        res, session = cherrypy.request.crowdapi.create_session(
                user, password)
        print 'SESSION', res
        if res != '201':
            return self.loginform(alert='Failed to establish new session.')
        cherrypy.request.crowd_token = session['token']

        cherrypy.request.crowd_user = user

        return True

    def preauth (self):
        if self.cookiename in cherrypy.request.cookie:
            print 'PREAUTH'

            cookie = cherrypy.request.cookie[self.cookiename]

            try:
                # Is pubtkt token still valid?
                pubtkt = ticket.Ticket(
                        urllib.unquote(cookie.value))
                cherrypy.request.pubtkt = pubtkt
                print 'PREAUTH TICKET:', pubtkt

                # Check signature (ticket.BadSignatureError on failure)
                pubtkt.verify(self.pubkey)
                print 'PREAUTH VERIFIED'

                # Has ticket expired?
                if pubtkt['validuntil'] < time.time():
                    return False
                print 'PREAUTH ACTIVE'

                cherrypy.request.crowd_user = pubtkt['uid']

                # Is Crowd authentication still valid?
                crowd_token = pubtkt['udata']
                res, data = cherrypy.request.crowdapi.verify_session(crowd_token)
                print 'PREAUTH RES:', res

                cherrypy.request.crowd_token = crowd_token
                return res == '200'

            except ticket.TicketError:
                pass

        return False

    def set_cookie_and_redirect (self):
        user = cherrypy.request.crowd_user

        # Get groups from Crowd.
        res,groups = cherrypy.request.crowdapi.request(
                'user/group/nested', username=user)
        groups = [x['name'] for x in groups.get('groups', [])]

        tkt = ticket.Ticket(uid=user,
                validuntil = self.validuntil,
                tokens = groups,
                udata = cherrypy.request.crowd_token,
                graceperiod = self.graceperiod)

        tkt.sign(self.privkey)
        print tkt.to_string(sig=True)

        cherrypy.response.cookie[self.cookiename] = urllib.quote(
                tkt.to_string(sig=True))
        
        back = cherrypy.request.params.get('back')
        if back:
            print 'REDIRECT', back
            raise cherrypy.HTTPRedirect(back)
        else:
            print 'CONFIRM'
            return self.pages.render('loginok',
                    macros=['common'],
                    user=user,
                    params=cherrypy.request.params,
                    request=cherrypy.request)

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

