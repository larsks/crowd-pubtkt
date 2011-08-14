import simplejson as json
import httplib2 as httplib
import urllib

class CrowdError (Exception):
    def __init__ (self, msg, resp=None, content=None):
        self.resp = resp
        self.content = content
        super(CrowdError, self).__init__(msg)

class Crowd (object):

    '''Wraps the Crowd REST API in some convenience
    functions.'''

    def __init__ (self, baseurl, crowd_name, crowd_pass, 
            apiname='usermanagement', apiversion='latest',
            novalidate=True):

        '''baseurl -- base URL of the Crowd instance
        crowd_name -- crowd application name
        crowd_pass -- crowd application password
        apiname -- name of the api ("usermanagement")
        apiversion -- api version ("latest")
        novalidate -- True to disable certificate validation
                      for SSL connections (True).
        '''

        self.baseurl = baseurl
        self.apiname = apiname
        self.apiversion = apiversion
        self.crowd_name = crowd_name
        self.crowd_pass = crowd_pass

        self.client = httplib.Http(
                disable_ssl_certificate_validation=novalidate)
        self.client.add_credentials(self.crowd_name, self.crowd_pass)

    def __str__ (self):
        return '<Crowd %s>' % self.crowd_name

    def request(self, uri, method='GET', postdata=None, debug=False, **params):
        # Turn the params dictionary into a query string,
        qs = '&'.join(['%s=%s' % (urllib.quote(k), urllib.quote(v)) for
            (k,v) in params.items()])

        # Build the complete URL from all the pieces.
        url = '%s/rest/%s/%s/%s.json?%s' % (
                self.baseurl,
                self.apiname,
                self.apiversion,
                uri, qs)

        body = None
        headers = {'Content-type': 'application/json'}

        if postdata is not None:
            method = 'POST'
            body = json.dumps(postdata)

        if debug:
            print '=== DEBUG ==='
            print 'URL:', url
            print 'BODY:', body
            print '=== DEBUG ==='

        resp,content = self.client.request(url, method,
                headers=headers, body=body)

        if resp['content-type'] != 'application/json':
            raise CrowdError('Did not receive JSON response.',
                    resp=resp, content=content)

        return resp['status'], json.loads(content)

    def authenticate(self, user, password):
        '''Authenticate a username and password.'''
        return self.request('authentication',
                postdata={ 'value': password },
                username=user)

    def create_session(self, user, password='', factors=None):
        if not password:
            uri = 'session/validate-password=false'
        else:
            uri = 'session'

        if factors is None:
            factors = []

        return self.request(uri,
                postdata={
                    'username': user,
                    'password': password,
                    'validation-factors': {
                        'validationFactors': factors
                        }
                    }
                )

    def verify_session(self, token, factors=None):
        if factors is None:
            factors = []

        return self.request('session/%s' % token,
                postdata = {
                    'validationFactors': factors
                    }
                )

if __name__ == '__main__':
    import sys

    cfoo = Crowd('https://id.seas.harvard.edu/crowd',
            'pubtkt-foo', 'UkyecUfzeymKivUcunye')
    cbar = Crowd('https://id.seas.harvard.edu/crowd',
            'pubtkt-bar', 'rovHeyftEgaikFoohyk2')

    print 'AUTHENTICATE'
    print '=' * 75
    for app in [cfoo, cbar]:
        for user in [['joeuser', 'hello'], ['joeuser', 'badpass'], ['janeuser', 'goodbye']]:
            res, content = app.authenticate(*user)
            print app, 'as', user[0], res
            print content

    print 'CREATE SESSION'
    print '=' * 75
    res, s1 = cfoo.request('session', postdata={
        'username': 'joeuser', 'password': 'hello'})
    print cfoo, 'as', 'joeuser', res, s1.get('token', '<NONE>') 
    res, s2 = cfoo.create_session('janeuser', 'goodbye',
            factors=[{'name': 'remote_address', 'value': '127.0.0.1'}])
    print cfoo, 'as', 'janeuser', res, s2.get('token', '<NONE>') 
    print s2

    res, s3 = cbar.request('session', postdata={
        'username': 'joeuser', 'password': 'hello'})
    print cbar, 'as', 'joeuser', res, s3.get('token', '<NONE>') 
    res, s4 = cbar.request('session', postdata={
        'username': 'janeuser', 'password': 'goodbye'})
    print cbar, 'as', 'janeuser', res, s4.get('token', '<NONE>') 

    print 'VALIDATE SESSION'
    print '=' * 75
    res, v1 = cfoo.verify_session(s2['token'],
            factors=[{'name': 'remote_address', 'value': '127.0.0.1'}])
    print cfoo, 'as', s2['user']['name'], res
    print v1
    res, v2 = cfoo.request('session/%s' % s3['token'],
            postdata = {})
    print cfoo, 'as', s3['user']['name'], res

