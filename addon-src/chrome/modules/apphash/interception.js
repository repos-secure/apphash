var EXPORTED_SYMBOLS = [
    "loadhashes", "savehashes", "apphashList", "bannedUrls",
    "is_watched_url"
];

Components.utils.import("resource://apphash/verification.js");  

const match_hostname = /.*localhost.*/;
const match_locker = "^/[^_].*";

const Cc = Components.classes;
const Ci = Components.interfaces;

var apphashList = [];
var bannedUrls = {};

// Helper function for XPCOM instantiation (from Firebug)
function CCIN(cName, ifaceName) {
    return Cc[cName].createInstance(Ci[ifaceName]);
}

// Copy response listener implementation.
function TracingListener(hash, url) {
    this.hash = hash;
    this.url = url;
    this.receivedData = [];   // array for incoming data.
}

TracingListener.prototype = {
    originalListener: null,
    onDataAvailable: function(request, context, inputStream, offset, count) {
        var binaryInputStream = CCIN("@mozilla.org/binaryinputstream;1",
                "nsIBinaryInputStream");
        var storageStream = CCIN("@mozilla.org/storagestream;1", "nsIStorageStream");
        var binaryOutputStream = CCIN("@mozilla.org/binaryoutputstream;1",
                "nsIBinaryOutputStream");

        binaryInputStream.setInputStream(inputStream);
        storageStream.init(8192, count, null);
        binaryOutputStream.setOutputStream(storageStream.getOutputStream(0));

        // Copy received data as they come.
        var data = binaryInputStream.readBytes(count);
        this.receivedData.push(data);

        binaryOutputStream.writeBytes(data, count);

        this.originalListener.onDataAvailable(request, context,
            storageStream.newInputStream(0), offset, count);
    },

    onStartRequest: function(request, context) {
        this.originalListener.onStartRequest(request, context);
    },

    onStopRequest: function(request, context, statusCode){
        var responseSource = this.receivedData.join("");
        var check = apphash_verify(responseSource, this.hash);
        if (check == "ok"){
            delete bannedUrls[this.url];
        } else {
            bannedUrls[this.url] = {
                got: check,
                expected: this.hash
            }        
        }
        saveurls();
        this.originalListener.onStopRequest(request, context, statusCode);
    },

    QueryInterface: function (aIID) {
        if (aIID.equals(Ci.nsIStreamListener) ||
            aIID.equals(Ci.nsISupports)) {
            return this;
        }
        throw Components.results.NS_NOINTERFACE;
    }
}

var httpRequestObserver = {
    observe: function(request, aTopic, aData) {
        if (aTopic == "http-on-examine-response"){
            request.QueryInterface(Components.interfaces.nsIHttpChannel);
            var ah = is_watched_url(request.URI.asciiSpec);
            if (ah){
                var newListener = new TracingListener(
                                        ah.hash,
                                        request.URI.asciiSpec
                                    );
                request.QueryInterface(Ci.nsITraceableChannel);
                newListener.originalListener = request.setNewListener(newListener);
            }
        }
    },

    QueryInterface : function (aIID) {
        if (aIID.equals(Ci.nsIObserver) || aIID.equals(Ci.nsISupports)){
            return this;
        }
        throw Components.results.NS_NOINTERFACE;
    }
};


function apphash_init() {
    const Cc = Components.classes;
    const Ci = Components.interfaces;
    loadhashes();
    loadurls();
    var observerService = Cc["@mozilla.org/observer-service;1"]
        .getService(Ci.nsIObserverService);
    observerService.addObserver(httpRequestObserver, "http-on-examine-response", false);
}

function _save(name, value) {
    var preferencesService = Components.classes["@mozilla.org/preferences-service;1"]
        .getService( Components.interfaces.nsIPrefService );
    var branch = preferencesService.getBranch("extensions.apphash.");
    return branch.setCharPref(name, JSON.stringify(value));
}

    
function _load(name, dvalue) {
    var preferencesService = Components.classes["@mozilla.org/preferences-service;1"]
        .getService( Components.interfaces.nsIPrefService );
    var branch = preferencesService.getBranch("extensions.apphash.");
    try {
        var value = branch.getCharPref(name);
    } catch (e) {
        return dvalue;
    }
    if (value)
        return JSON.parse(value);
    else
        return dvalue;
}

function is_watched_url(u){
    for (i = 0; i < apphashList.length; i++){
        if (u.match(apphashList[i].regex))
            return apphashList[i];
    }
    return false;
}

function savehashes() {
    _save("hashes", apphashList);
    /* Whenever we save hashes, we also need to remove stale entries from the
     * bannedUrls list. */
    for (var u in bannedUrls){
        if (!is_watched_url(u))
            delete bannedUrls[u];
    }
    saveurls();
}

function loadhashes() {
    apphashList = _load("hashes", []);
}


function saveurls() {
    _save("urls", bannedUrls);
}

function loadurls() {
    bannedUrls = _load("urls", {});
}

apphash_init();

