import hashlib
import base64
import datetime
import time

import M2Crypto
from M2Crypto import RSA

class TicketError(Exception):
    pass

class MissingFieldError (TicketError):
    pass

class BadSignatureError (TicketError):
    pass

def split_token(tok):
    return dict([x.split('=',1) for x in tok.split(';')])

class Ticket (dict):

    def __init__(self, ticket=None, *args, **kwargs):
        super(Ticket, self).__init__(*args, **kwargs)

        #       field           xform_out       xform_in    required
        self.fields = [
                ('uid',	        str,	        str,        True),
                ('validuntil',	self.parsedate,	int,        True),
                ('cip',	        str,        	str,        False),
                ('tokens',	    lambda x: ','.join(x),
                                                lambda x: x.split(','),
                                                False),
                ('udata',	    str,	        str,        False),
                ('graceperiod',	self.parsedate,	int,        False),
                ('sig',         str,            str,        False),
                ]

        if ticket is not None:
            if isinstance(ticket, dict):
                self.from_dict(ticket)
            else:
                self.from_string(ticket)

    def from_dict (self, ticket):
        self.update(ticket)

    def from_string (self, ticket):
        self.update(split_token(ticket))

        for fspec in self.fields:
            if fspec[3] and not fspec[0] in self:
                raise MissingFieldError('missing required field: %s' %
                        fspec[0])
            elif fspec[0] in self:
                self[fspec[0]] = fspec[2](self[fspec[0]])

    def freeze (self):
        '''Makes sure that dynamic values (like datetime.timedelta) get
        turned into static values.'''
        self.from_string(self.to_string())

    def parsedate(self, d):
        if isinstance(d, datetime.timedelta):
            d = datetime.datetime.now() + d

        if isinstance(d, datetime.datetime):
            d = time.mktime(d.timetuple())

        return int(d)

    def to_string (self, sig=False):
        dtok = []

        for fspec in self.fields:
            if fspec[0] == 'sig' and not sig:
                continue

            if fspec[3] and not fspec[0] in self:
                raise MissingFieldError('missing required field: %s' %
                        fspec[0])
            elif fspec[0] in self:
                dtok.append('%s=%s' % (fspec[0],
                    fspec[1](self[fspec[0]])))

        stok = ';'.join(dtok)
        return stok

    def sign (self, privkey):
        if isinstance(privkey, str):
            privkey = RSA.load_key(privkey)

        # If we're signing the ticket, we need to make sure
        # it won't change.
        self.freeze()

        tok = self.to_string()
        dgst = hashlib.sha1(tok).digest()
        sig = privkey.sign(dgst, 'sha1')
        sig = base64.b64encode(sig)

        self['sig'] = sig

    def verify(self, pubkey):
        if isinstance(pubkey, str):
            pubkey = RSA.load_pub_key(pubkey)

        tok = self.to_string()
        dgst = hashlib.sha1(tok).digest()
        sig = base64.b64decode(self['sig'])

        try:
            return pubkey.verify(dgst, sig, 'sha1')
        except M2Crypto.RSA.RSAError, detail:
            raise BadSignatureError(detail)

    def __str__ (self):
        return self.to_string()

if __name__ == '__main__':
    t1 = Ticket(uid='lars', validuntil=datetime.timedelta(hours=1),
            tokens=['one', 'two', 'three'],
            udata='This is some random user data.')

    print 'created token'
    print t1.to_string()

    print 'sign'
    t1.sign('privkey.pem')
    time.sleep(1)

    print 'verify'
    if t1.verify('pubkey.pem'):
        print 'good sig'
    else:
        print 'bad sig'

    print 'invalidating token'
    t1['uid'] = 'bad'
    t1.verify('pubkey.pem')

