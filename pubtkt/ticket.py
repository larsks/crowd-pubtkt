import hashlib
import base64
import datetime
import time

from M2Crypto import RSA

class TicketError(Exception):
    pass

class MissingFieldError (TicketError):
    pass

def split_token(tok):
    return dict([x.split('=',1) for x in tok.split(';')])

class Ticket (dict):

    def __init__(self, ticket=None, *args, **kwargs):
        super(Ticket, self).__init__(*args, **kwargs)

        self.fields = [
                ('uid',	        str,	        True),
                ('validuntil',	self.parsedate,	True),
                ('cip',	        str,        	False),
                ('tokens',	    lambda x: ','.join(x),
                                                False),
                ('udata',	    str,	        False),
                ('graceperiod',	self.parsedate,	False),
                ('sig',         str,            False),
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
        self['tokens'] = self.get('tokens', '').split(',')

    def parsedate(self, d):
        if isinstance(d, datetime.timedelta):
            d = datetime.datetime.now() + d

        if isinstance(d, datetime.datetime):
            d = time.mktime(d.timetuple())

        return int(d)

    def ticket (self):
        dtok = []

        for fspec in self.fields:
            if fspec[2] and not fspec[0] in self:
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

        stok = self.ticket()

        dgst = hashlib.sha1(stok).digest()
        sig = privkey.sign(dgst, 'sha1')
        sig = base64.b64encode(sig)

        self['sig'] = sig

    def __str__ (self):
        return self.ticket()

if __name__ == '__main__':
    t1 = Ticket(uid='lars', validuntil=datetime.timedelta(hours=1),
            tokens=['one', 'two', 'three'])

