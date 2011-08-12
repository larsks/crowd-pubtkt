import simplejson as json
import httplib2 as httplib
import urllib

class CrowdError (Exception):
    def __init__ (self, msg, resp=None, content=None):
        self.resp = resp
        self.content = content
        super(CrowdError, self).__init__(msg)

class Crowd (object):

    def __init__ (self, baseurl, crowd_name, crowd_pass, 
            apiname='usermanagement', apiversion='latest',
            novalidate=True):

        self.baseurl = baseurl
        self.apiname = apiname
        self.apiversion = apiversion
        self.crowd_name = crowd_name
        self.crowd_pass = crowd_pass

        self.client = httplib.Http(
                disable_ssl_certificate_validation=novalidate)
        self.client.add_credentials(self.crowd_name, self.crowd_pass)

    def request(self, uri, postdata=None, **params):
        # Turn the params dictionary into a query string,
        qs = '&'.join(['%s=%s' % (urllib.quote(k), urllib.quote(v)) for
            (k,v) in params.items()])

        url = '%s/rest/%s/%s/%s.json?%s' % (
                self.baseurl,
                self.apiname,
                self.apiversion,
                uri, qs)

        if postdata is not None:
            method = 'POST'
            headers = {'Content-type': 'application/json'}
            body = json.dumps(postdata)
        else:
            method = 'GET'
            headers = {}
            body = None

        print 'REQUEST:', method, url
        if body is not None:
            print 'BODY:'
            print body

        resp,content = self.client.request(url, method,
                headers=headers, body=body)

        if resp['content-type'] != 'application/json':
            raise CrowdError('Did not receive JSON response.',
                    resp=resp, content=content)

        return resp['status'], json.loads(content)

    def authenticate(self, user, password):
        return self.request('authenticate',
                postdata={ 'value': password },
                username=user)

if __name__ == '__main__':
    import sys

    try:
        c = Crowd('https://id.seas.harvard.edu/crowd',
                'pubtkt-foo', 'UkyecUfzeymKivUcunye')
        print c.request('user', username=sys.argv[1])
    except CrowdError, detail:
        print 'Response:', detail.resp
        print 'Content:', detail.content
        raise

