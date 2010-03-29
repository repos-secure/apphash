Components.utils.import("resource://apphash/interception.js");  


function apphash_tabselect(e) {
    var url = getWebNavigation().currentURI.asciiSpec;
    if (is_watched_url(url)) {
        if (bannedUrls[url]){
            document.getElementById("apphash-statusbar").style.color = "red";
            getBrowser().loadURI("chrome://apphash/content/failure.xul");
        } else
            document.getElementById("apphash-statusbar").style.color = "green";
    } else {
        document.getElementById("apphash-statusbar").style.color = "white";
    }
}


function apphash_init() {
    var container = gBrowser.tabContainer;
    container.addEventListener("TabSelect", apphash_tabselect, false);
    container.addEventListener("TabOpen", check_page, false);
    container.addEventListener("TabOpen", apphash_tabselect, false);
    container.addEventListener("pageshow", apphash_tabselect, true);        
    gBrowser.addEventListener("load", apphash_tabselect, true);
}


function apphash_change_hash() {
    window.open(
        "chrome://apphash/content/options.xul",
        "apphash-options-dialog",
        "centerscreen,chrome,resizable"
    );
}


function initmodal() {
    document.getElementById("url").setAttribute("value", window.arguments[0]);
    document.getElementById("expected").setAttribute(
        "value",
        window.arguments[1].expected
    );
    document.getElementById("got").setAttribute(
        "value",
        window.arguments[1].got
    );
}


// Do we need to check all frames
// What happens if tab loads in background? Do we need to run this when tabs switch?
function check_page(){
    var url = getWebNavigation().currentURI.asciiSpec;
    if (bannedUrls[url]){
        // This seems to do the trick, but there might be a better way.  The
        // aim is to get the user away from the page, in a way that prevents
        // malicious code from interfering with the warning message. An overlay
        // or manipulation of the page DOM won't do. It would be nice to
        // preserve the original URL in the location bar here...
        var browser = getBrowser();
        browser.loadURI("chrome://apphash/content/failure.xul");
        window.openDialog(
            "chrome://apphash/content/failure-modal.xul",
            "",
            "chrome,centerscreen,modal,close",
            url,
            bannedUrls[url]
        )
    } else if (is_watched_url(url)) {
        document.getElementById("apphash-statusbar").style.color = "green";
    }
}


function apphash_accept_options() {
    var v = document.getElementById("apphash_newhash").value;
    if (v)
        sethash(v)
}


const names = ["name", "regex", "hash"];
var hashManager = {
    _tree : null,
    _removeButton : null,
    _changeButton : null,

    init: function() {
        (this._removeButton = document.getElementById("removeHash")).disabled = true;
        (this._changeButton = document.getElementById("changeHash")).disabled = true;
        this._tree = document.getElementById("hashList");
        this._treeView = {
            selection: null,
            get rowCount() { return apphashList.length; },
            getCellText: function(row, column) {
                switch(column.id) {
                    case "name":
                        return " " + apphashList[row].name;
                    case "regex":
                        return apphashList[row].regex;
                    case "hash":
                        return apphashList[row].hash;
                }
                return "";
            },
            setTree: function(treebox){ this.treebox = treebox; },
            isContainer: function(row) { return false; },
            isContainerOpen: function(row) { return false; },
            isContainerEmpty: function(row) { return false; },
            isSeparator: function(row) { return false; },
            isSorted: function() { return false; },
            getLevel: function(row) { return 0; },
            getImageSrc: function(row,column) { },
            getRowProperties: function(row,props) {},
            getCellProperties: function(row,column,props) {},
            getColumnProperties: function(colid,column,props) {}
        };
        this._tree.view = this._treeView;
    },

    onSelectionChanged: function() {
        var selection = this._tree.view.selection;
        this._removeButton.disabled = (selection.count != 1);
        this._changeButton.disabled = (selection.count != 1);
    },

    addHandler: function() {
        var item = { name: "", regex: "", hash: "" };
        var result = {};
        openDialog(
            "chrome://apphash/content/changehash.xul",
            "_blank",
            "modal,centerscreen",
            item,
            result
        );
        if (result.saveChanges) {
            apphashList.push(item);
            this._save()
        }
    },

    removeHandler: function() {
        var selection = this._tree.view.selection;
        if (selection.count < 1)
            return;
        apphashList.splice(selection.currentIndex, 1)
        this._save()
    },

    changeHandler: function() {
        var selection = this._tree.view.selection;
        if (selection.count != 1)
            return;
        var item = apphashList[selection.currentIndex];
        var result = {};
        openDialog(
            "chrome://apphash/content/changehash.xul",
            "_blank",
            "modal,centerscreen",
            item,
            result
        );
        if (result.saveChanges) {
            apphashList.splice(selection.currentIndex, 1, item);
        }
        this._save()
    },

    _save: function() {
        savehashes();
        this._tree.view = this._treeView;
    },
};

