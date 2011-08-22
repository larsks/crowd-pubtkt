import httplib2
import urllib
import simplejson as json
import memcache

METHODS = [ 'get', 'post', 'put', 'delete' ]

class RESTError(Exception):
    pass

class APIError (RESTError):
    def __init__ (self, method, uri, resp, content):
        self.method = method
        self.uri = uri
        self.resp = resp
        self.content = content

        super(APIError, self).__init__('Error %s from %s' %
                (resp['status'], uri))

class ObjectNotFound (RESTError):
    pass

class RESTClient (object):
    def __init__(self, baseurl, credentials,
            apiname='usermanagement',
            apiversion='latest'):
        self.baseurl = baseurl
        self.credentials = credentials
        self.apiname = apiname
        self.apiversion = apiversion
        self.cache = memcache.Client(['127.0.0.1:11211'])

    def __getattr__ (self, k):
        return Component(k, self, self)

    def _uri(self):
        return None

class Component (object):
    def __init__(self, name, parent, api):
        self.name = name
        self.parent = parent
        self.api = api

    def __str__(self):
        return '<Component %s>' % self.name

    def __getattr__ (self, k):
        if k in METHODS:
            return self._method(k)
        else:
            return Component(k, self, self.api)

    def _method(self, k):
        '''Returns a wrapper on self.request that passes in the
        correct HTTP method and otherwise massages the request.'''

        def _(*args, **kwargs):
            kwargs.setdefault('body', {})
            if args:
                kwargs.setdefault('path_info', args[0])

            return self.request(k.upper(), self.uri(), **kwargs)

        _.__name__ = '%s.%s' % (self.uri(), k.upper())
        return _

    def __call__ (self, *args, **kwargs):
        '''If you call a component (e.g., api.user()), it's the same
        as calling component.get() (e.g., api.user.get()).'''
        return self.get(*args, **kwargs)

    def _uri(self):
        p = self.parent._uri()
        if p is not None:
            return [self.name] + p
        else:
            return [self.name]

    def uri(self):
        '''Return the URI of this component.'''
        return '/'.join(reversed(self._uri()))

    def request(self, method, uri,
            path_info='', body=None, **params):
        qs = urllib.urlencode([(k.replace('_', '-'), v) for k,v in
                params.items()])

        client = httplib2.Http(
                disable_ssl_certificate_validation=True)
        client.add_credentials(*self.api.credentials)

        url = '%s/rest/%s/%s/%s%s?%s' % (
                self.api.baseurl,
                self.api.apiname,
                self.api.apiversion,
                uri, path_info, qs)

        headers = {
                'Content-type'  : 'application/json',
                'Accept'  : 'application/json',
                }

        if body is not None:
            body = json.dumps(body)

        resp,content = client.request(url, method,
                headers=headers, body=body)

        if resp['content-type'] == 'application/json':
            content = json.loads(content)

        if resp['status'].startswith('5'):
            raise APIError(method, uri, resp, content)
        if resp['status'] == '404':
            raise ObjectNotFound(url)

        return resp['status'], content

if __name__ == '__main__':
    creds=('pubtkt-bar', 'rovHeyftEgaikFoohyk2')
    a = RESTClient('https://id.seas.harvard.edu/crowd', creds)

    print 'Check cookie config.'
    res, content = a.config.cookie()
    assert res == '200'
    assert content['name'] == 'crowd.token_key'

    print 'Check invalid request.'
    assert a.user()[0] == '400'

    print 'Check users.'
    assert a.user(username='joeuser')[0] == '200'
    assert a.user(username='janeuser')[0] == '200'

    print 'Check groups.'
    assert a.group(groupname='test-group-2')[0] == '200'

    print 'Check session create.'
    # janeuser does not have access to pubtkt-bar
    res, content = a.session.post(validate_password='false',
            body={'username': 'janeuser'})
    assert res == '403'

    # joeuser does.
    res, content = a.session.post(validate_password='false',
            body={'username': 'joeuser'})
    assert res == '201'
    token = content['token']

    print 'Check session validate.'
    res, content = a.session.post('/%s' % token)
    assert res == '200'

    print 'Check session delete.'
    res, content = a.session.delete('/%s' % token)
    assert res == '204'

    detail = None
    try:
        res, content = a.session.post('/%s' % token)
    except ObjectNotFound, detail:
        pass
    assert isinstance(detail, ObjectNotFound)

    print 'Check unknown method call.'
    detail = None
    try:
        res, content = a.does_not_exist()
    except ObjectNotFound, detail:
        pass
    assert isinstance(detail, ObjectNotFound)

    print 'All assertions passed.'

