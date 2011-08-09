import hashlib
import base64
from M2Crypto import RSA
import datetime
import time

class TicketError(Exception):
    pass

class MissingFieldError (TicketError):
    pass

class Ticket (dict):

    def __init__(self, privkey, *args, **kwargs):
        super(Ticket, self).__init__(*args, **kwargs)
        self.privkey = privkey

        self.fields = [
                ('uid',	        str,	        True),
                ('validuntil',	self.parsedate,	True),
                ('cip',	        str,        	False),
                ('tokens',	    lambda x: ','.join(x),
                                                False),
                ('udata',	    str,	        False),
                ('graceperiod',	self.parsedate,	False),
                ]

    def parsedate(self, d):
        if isinstance(d, datetime.timedelta):
            d = datetime.datetime.now() + d

        if isinstance(d, datetime.datetime):
            d = time.mktime(d.timetuple())

        return d

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
        dgst = hashlib.sha1(stok).digest()
        sig = self.privkey.sign(dgst, 'sha1')
        sig = base64.b64encode(sig)

        return '%s;sig=%s' % (stok, sig)

    def __str__ (self):
        return self.ticket()

if __name__ == '__main__':
    k = RSA.load_key('privkey.pem')
    p = Ticket(k, uid='lars',
            validuntil = datetime.timedelta(minutes=10),
            graceperiod = datetime.timedelta(minutes=5))

    print p

