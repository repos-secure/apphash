import os.path, hashlib, textwrap, json
import cubictemp
import libpry
from liblocker import utils, locker
import _utils


class O(object): pass

def hash(s):
    h = hashlib.sha256()
    h.update(s)
    return h.hexdigest()



class uVerification(_utils.RenderTester):
    COMPONENTS = [
        "./components/jquery-1.3.2.js",
        "../addon-src/chrome/modules/apphash/verification.js"
    ]
    def test_sha(self):
        teststrings = [
            "", "a", "aa", "aaa", "aaaa", "aaaaaa", "asdf"*10,
            "".join([chr(j) for j in range(256)]),
        ]
        self._testFile(
            "sha.html",
            numstrings = len(teststrings),
            teststrings = json.dumps(teststrings, encoding="latin-1"),
            hashes = json.dumps([hash(i) for i in teststrings])
        )

    def test_sha_long(self):
        def hash(s):
            h = hashlib.sha256()
            h.update(s)
            return h.hexdigest()
        #teststrings = [
            #"a"*51,
            #"a"*52,
        #]
        teststrings = []
        for  i in range(1024):
            teststrings.append(
                "a"*i,
            )
        self._testFile(
            "sha_long.html",
            numstrings = len(teststrings),
            teststrings = json.dumps(teststrings, encoding="latin-1"),
            hashes = json.dumps([hash(i) for i in teststrings])
        )

    def test_hostile(self):
        self._testFile("hostile.html")

    def test_split(self):
        teststrings = [
            """
                test
            """,
            """
                // APPHASH_HOSTILE_ZONE
            """,
            """
                a
                // APPHASH_HOSTILE_ZONE
                h
                // APPHASH_HOSTILE_ZONE
                b
            """,
            """
                a
                // APPHASH_HOSTILE_ZONE
                h
                // APPHASH_HOSTILE_ZONE
                // APPHASH_HOSTILE_ZONE
                b
            """,
        ]
        teststrings = [textwrap.dedent(i).strip() for i in teststrings]
        escstrings = [utils.jsquote(i) for i in teststrings]
        self._testFile(
            "split.html",
            teststrings = teststrings,
            escstrings = escstrings,
        )

    def test_verify(self):
        teststrings = [
            (
                "ok",
                r"""
                    test
                """
            ),
            (
                "ok",
                r"""
                    // APPHASH_HOSTILE_ZONE
                """
            ),
            (
                "non-assignment line in hostile block",
                r"""
                    a
                    // APPHASH_HOSTILE_ZONE
                    h
                    // APPHASH_HOSTILE_ZONE
                    b
                """
            ),
            (
                "non-assignment line in hostile block",
                r"""
                    a
                    // APPHASH_HOSTILE_ZONE
                    h
                    // APPHASH_HOSTILE_ZONE
                    // APPHASH_HOSTILE_ZONE
                    b
                """
            ),
            (
                "ok",
                r"""
                    a
                    // APPHASH_HOSTILE_ZONE
                    var x = "foo";
                    // APPHASH_HOSTILE_ZONE
                    b
                """
            ),
            (
                "non-assignment line in hostile block",
                r"""
                    premature string termination
                    // APPHASH_HOSTILE_ZONE
                    var x = "foo\";
                    // APPHASH_HOSTILE_ZONE
                """
            ),
            (
                "unescaped special character in string assignment",
                r"""
                    quote contamination
                    // APPHASH_HOSTILE_ZONE
                    var x = "fo'o";
                    // APPHASH_HOSTILE_ZONE
                """
            ),
            (
                "unescaped special character in string assignment",
                r"""
                    quote contamination
                    // APPHASH_HOSTILE_ZONE
                    var a = "foo";
                    var x = "fo"o";
                    // APPHASH_HOSTILE_ZONE
                """
            ),
            (
                "hanging backslash in string assignment",
                r"""
                    backslash contamination
                    // APPHASH_HOSTILE_ZONE
                    var a = "foo";
                    var x = "fo\o";
                    // APPHASH_HOSTILE_ZONE
                """
            ),
            (
                "ok",
                r"""
                    escaping
                    // APPHASH_HOSTILE_ZONE
                    var a = "foo";
                    var x = "fo\\\'\"o";
                    // APPHASH_HOSTILE_ZONE
                """
            ),
            (
                "ok",
                """
                    all 256 valid bytes
                    // APPHASH_HOSTILE_ZONE
                    var a = "foo";
                    var x = "%s";
                    // APPHASH_HOSTILE_ZONE
                """%(utils.jsquote("".join([chr(j) for j in range(255)])))
            ),
            (
                "non-assignment line in hostile block",
                """
                    line breaks 
                    // APPHASH_HOSTILE_ZONE
                    var x = "%s";
                    // APPHASH_HOSTILE_ZONE
                """%("x\rx")
            ),
            (
                "non-assignment line in hostile block",
                """
                    line breaks
                    // APPHASH_HOSTILE_ZONE
                    var x = "%s";
                    // APPHASH_HOSTILE_ZONE
                """%("x\nx")
            ),
            (
                "ok",
                """
                    realworld - new lockej
                    // APPHASH_HOSTILE_ZONE
                        var name = "b";
                        var domain = "http://localhost:8080/";
                        var writekey = "38ed7c071d627fdc70476180183a1820da9fcfd8";
                        var ciphertext = "";
                    // APPHASH_HOSTILE_ZONE
                """
            ),
        ]
        tstrings = []
        for i, e in enumerate(teststrings):
            c = O()
            c.i = i
            c.expected = e[0]
            c.raw = textwrap.dedent(e[1]).strip().decode("latin-1")
            c.quoted = utils.jsquote(c.raw)
            c.hash = locker.hash(c.raw, True)
            tstrings.append(c)


        self._testFile(
            "verify.html",
            tstrings = tstrings,
        )


tests = [
    uVerification()
]
