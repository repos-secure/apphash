import os, os.path
import libpry, cubictemp
from liblocker import utils, locker

OUTDIR = "browser"

class RenderTester(libpry.AutoTree):
    COMPONENTS = []
    def setUpAll(self):
        if not os.path.exists(OUTDIR):
            os.mkdir(OUTDIR)

    def _existingLocker(self, fname, domain, name, data):
        f = open(os.path.join(OUTDIR, fname), "wb")
        l = locker.Locker(domain, False, False)
        f.write(l.existing(name, data))

    def _testFile(self, name, **kwargs):
        js = []
        for i in self.COMPONENTS:
            f = file(i)
            js.append(f.read())
        kwargs["js"] = js
        t = cubictemp.File(os.path.join("templates", name), **kwargs)
        f = open(os.path.join(OUTDIR, name), "wb")
        f.write(t.raw().encode("latin-1"))

