import os
import sys
import errno

from cStringIO import StringIO

from simpletal import simpleTAL, simpleTALES

class PageError (Exception):
    pass

class PageCache (dict):

    '''This class is responsible for loading and compiling 
    templates.  It will reload templates if they have been
    modified since the template was last loaded.'''

    def __init__ (self, templatedir):
        if not os.path.exists(templatedir):
            raise PageError('Directory "%s" does not exist' % templatedir)

        super(PageCache, self).__init__()

        self.cache = {}
        self.templatedir = templatedir

    def load (self, k):
        template_path = os.path.join(self.templatedir, '%s.html' % k)
        template = simpleTAL.compileHTMLTemplate(open(template_path))
        mtime = os.stat(template_path).st_mtime

        v = {   'name':     k,
                'path':     template_path,
                'mtime':    mtime,
                'template': template
                }

        self.cache[k] = v
        return v

    def __getitem__ (self, k):
        '''Return a compiled template.  If the template on disk
        has not been modified since we last read it, return the
        cached version; otherwise recompile the template by
        calling self.load().'''

        try:
            v = super(PageCache, self).__getitem__(k)
            if os.stat(v['path']).st_mtime > v['mtime']:
                raise KeyError
        except KeyError:
            try:
                v = self.load(k)
            except OSError, detail:
                if detail.errno == errno.ENOENT:
                    raise KeyError(k)
                else:
                    raise

        return v['template']

class Pages (object):
    '''A class for rendering page templates.'''

    def __init__ (self, templatedir, **ctxvals):
        self.cache = PageCache(templatedir)
        self.globals = ctxvals

    def compile(self, page):
        '''Return the compiled version of a template.'''
        return self.cache[page]

    def setGlobalContext(self, k, v):
        self.globals[k] = v

    def render (self, page, macros=None, **ctxvals):
        '''Render a template to HTML (and return the HTML as
        a string.'''

        ctx = simpleTALES.Context()

        for k,v in self.globals.items() + ctxvals.items():
            ctx.addGlobal(k, v)

        if macros is not None:
            for macro in macros:
                ctx.addGlobal(macro, self.cache[macro])

        buf = StringIO()
        self.cache[page].expand(ctx, buf)
        return buf.getvalue()

if __name__ == '__main__':

    p = Pages('templates')

