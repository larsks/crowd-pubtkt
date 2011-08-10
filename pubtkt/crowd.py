import simplejson as json
import httplib2 as httplib
import urllib

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

    def request(self, method, **params):
        qs = '&'.join(['%s=%s' % (urllib.quote(k), urllib.quote(v)) for
            (k,v) in params.items()])
        url = '%s/rest/%s/%s/%s.json?%s' % (
                self.baseurl,
                self.apiname,
                self.apiversion,
                method, qs)
        resp, content = self.client.request(url)
        return json.loads(content)

if __name__ == '__main__':

    c = Crowd('https://id.seas.harvard.edu/crowd',
            'pubtkt-foo', 'UkyecUfzeymKivUcunye')
    print c.request('user', username='lars')
