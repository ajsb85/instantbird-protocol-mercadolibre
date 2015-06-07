/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const {classes: Cc, interfaces: Ci, results: Cr, utils: Cu} = Components;

Cu.import("resource://gre/modules/Http.jsm");
Cu.import("resource:///modules/imServices.jsm");
Cu.import("resource:///modules/imXPCOMUtils.jsm");
Cu.import("resource:///modules/jsProtoHelper.jsm");

const NS_PREFBRANCH_PREFCHANGE_TOPIC_ID = "nsPref:changed";
const kMaxMessageLength = 140;

XPCOMUtils.defineLazyGetter(this, "_", function()
  l10nHelper("chrome://prpl-meli/locale/meli.properties")
);

function Conversation(aAccount)
{
  this._init(aAccount);
}
Conversation.prototype = {
  _disconnected: false,
  _setDisconnected: function() {
    this._disconnected = true;
  },
  close: function() {
    if (!this._disconnected)
      this.account.disconnect(true);
  },
  sendMsg: function (aMsg) {
    if (this._disconnected) {
      this.writeMessage("meli", "This message could not be sent because the conversation is no longer active: " + aMsg, {system: true, error: true});
      return;
    }

    this.writeMessage("You", aMsg, {outgoing: true});
    this.writeMessage("/dev/null", "Thanks! I appreciate your attention.",
                      {incoming: true, autoResponse: true});
  },

  get name() "/dev/null",
};
Conversation.prototype.__proto__ = GenericConvIMPrototype;

function Account(aProtoInstance, aImAccount)
{
  this._init(aProtoInstance, aImAccount);
}
Account.prototype = {
  // The correct normalization for twitter would be just toLowerCase().
  // Unfortunately, for backwards compatibility we retain this normalization,
  // which can cause edge cases for usernames with underscores.
  normalize: function(aString) aString.replace(/[^a-z0-9]/gi, "").toLowerCase(),

  consumerKey: Services.prefs.getCharPref("chat.mercadolibre.clientID"),
  //consumerSecret: Services.prefs.getCharPref("chat.mercadolibre.consumerSecret"),
  completionURI: "http://oauthcallback.local/",
  //http://auth.mercadolibre.com.ar/authorization?response_type=token&client_id=3530768295267429
  baseURI: "https://api.twitter.com/",
  token: "",
  tokenSecret: "",
  connect: function() {
    if (this.connected || this.connecting)
      return;
    this.reportConnecting();
    // Get a new token if needed...
    if (!this.token || !this.tokenSecret) {
      this.requestToken();
      return;
    }

    this.LOG("Connecting using existing token");
    this.reportConnected();
    setTimeout((function() {
      this._conv = new Conversation(this);
      this._conv.writeMessage("meli", "You are now talking to /dev/null", {system: true});
    }).bind(this), 0);
  },
  

  observe: function(aSubject, aTopic, aMsg) {
    // Twitter doesn't broadcast the user's availability, so we can ignore
    // imIUserStatusInfo's status notifications.
    if (aTopic != NS_PREFBRANCH_PREFCHANGE_TOPIC_ID)
      return;

    // Reopen the stream with the new tracked keywords.
    this.DEBUG("Twitter tracked keywords modified: " + this.getString("track"));

    // Close the stream and reopen it.
    this._streamingRequest.abort();
    this.openStream();
  },

  signAndSend: function(aUrl, aHeaders, aPOSTData, aOnLoad, aOnError, aThis,
                        aOAuthParams) {
    const kChars =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
    const kNonceLength = 6;
    let nonce = "";
    for (let i = 0; i < kNonceLength; ++i)
      nonce += kChars[Math.floor(Math.random() * kChars.length)];

    let params = (aOAuthParams || []).concat([
      ["oauth_consumer_key", this.consumerKey],
      ["oauth_nonce", nonce],
      ["oauth_signature_method", "HMAC-SHA1"],
      ["oauth_token", this.token],
      ["oauth_timestamp", Math.floor(((new Date()).getTime()) / 1000)],
      ["oauth_version", "1.0"]
    ]);

    let dataParams = [];
    let url = /^https?:/.test(aUrl) ? aUrl : this.baseURI + aUrl;
    let urlSpec = url;
    let queryIndex = url.indexOf("?");
    if (queryIndex != -1) {
      urlSpec = url.slice(0, queryIndex);
      dataParams = url.slice(queryIndex + 1).split("&")
                      .map(function(p) p.split("=").map(percentEncode));
    }
    let method = "GET";
    if (aPOSTData) {
      method = "POST";
      aPOSTData.forEach(function (p) {
        dataParams.push(p.map(percentEncode));
      });
    }

    let signatureKey = this.consumerSecret + "&" + this.tokenSecret;
    let signatureBase =
      method + "&" + encodeURIComponent(urlSpec) + "&" +
      params.concat(dataParams)
            .sort(function(a,b) (a[0] < b[0]) ? -1 : (a[0] > b[0]) ? 1 : 0)
            .map(function(p) p.map(encodeURIComponent).join("%3D"))
            .join("%26");

    let keyFactory = Cc["@mozilla.org/security/keyobjectfactory;1"]
                     .getService(Ci.nsIKeyObjectFactory);
    let hmac =
      Cc["@mozilla.org/security/hmac;1"].createInstance(Ci.nsICryptoHMAC);
    hmac.init(hmac.SHA1,
              keyFactory.keyFromString(Ci.nsIKeyObject.HMAC, signatureKey));
    // No UTF-8 encoding, special chars are already escaped.
    let bytes = [b.charCodeAt() for each (b in signatureBase)];
    hmac.update(bytes, bytes.length);
    let signature = hmac.finish(true);

    params.push(["oauth_signature", encodeURIComponent(signature)]);

    let authorization =
      "OAuth " + params.map(function (p) p[0] + "=\"" + p[1] + "\"").join(", ");

    let options = {
      headers: (aHeaders || []).concat([["Authorization", authorization]]),
      postData: aPOSTData,
      onLoad: aOnLoad ? aOnLoad.bind(aThis) : null,
      onError: aOnError ? aOnError.bind(aThis) : null,
      logger: {log: this.LOG.bind(this),
               debug: this.DEBUG.bind(this)}
    }
    return httpRequest(url, options);
  },
  _parseURLData: function(aData) {
    let result = {};
    aData.split("&").forEach(function (aParam) {
      let [key, value] = aParam.split("=");
      result[key] = value;
    });
    return result;
  },

  _conv: null,
  disconnect: function(aSilent) {
    this.reportDisconnecting(Components.interfaces.prplIAccount.NO_ERROR, "");
    if (!aSilent)
      this._conv.writeMessage("meli", "You have disconnected.", {system: true});
    if (this._conv) {
      this._conv._setDisconnected();
      delete this._conv;
    }
    this.reportDisconnected();
  },

  get canJoinChat() true,
  chatRoomFields: {
    channel: {label: "_Channel Field", required: true},
    channelDefault: {label: "_Field with default", default: "Default Value"},
    password: {label: "_Password Field", default: "", isPassword: true,
               required: false},
    sampleIntField: {label: "_Int Field", default: 4, min: 0, max: 10,
                     required: true}
  },
  

  requestToken: function() {
    this.reportConnecting(_("connection.initAuth"));
    let oauthParams =
      [["oauth_callback", encodeURIComponent(this.completionURI)]];
    this.signAndSend("oauth/request_token", null, [],
                     this.onRequestTokenReceived, this.onError, this,
                     oauthParams);
  },
  onRequestTokenReceived: function(aData) {
    this.LOG("Received request token.");
    let data = this._parseURLData(aData);
    if (!data.oauth_callback_confirmed ||
        !data.oauth_token || !data.oauth_token_secret) {
      this.gotDisconnected(Ci.prplIAccount.ERROR_OTHER_ERROR,
                           _("connection.failedToken"));
      return;
    }
    this.token = data.oauth_token;
    this.tokenSecret = data.oauth_token_secret;

    this.requestAuthorization();
  },
  requestAuthorization: function() {
    this.reportConnecting(_("connection.requestAuth"));
    let url = this.baseURI + "oauth/authorize?" +
      "force_login=true&" + // ignore cookies
      "screen_name=" + this.name + "&" + // prefill the user name input box
      "oauth_token=" + this.token;
    this._browserRequest = {
      get promptText() _("authPrompt"),
      account: this,
      url: "http://auth.mercadolibre.com.ar/authorization?response_type=token&client_id=3530768295267429",
      _active: true,
      cancelled: function() {
        if (!this._active)
          return;

        this.account
            .gotDisconnected(Ci.prplIAccount.ERROR_AUTHENTICATION_FAILED,
                             _("connection.error.authCancelled"));
      },
      loaded: function(aWindow, aWebProgress) {
        if (!this._active)
          return;

        this._listener = {
          QueryInterface: XPCOMUtils.generateQI([Ci.nsIWebProgressListener,
                                                 Ci.nsISupportsWeakReference]),
          _cleanUp: function() {
            this.webProgress.removeProgressListener(this);
            this.window.close();
            delete this.window;
          },
          _checkForRedirect: function(aURL) {
            if (!aURL.startsWith(this._parent.completionURI))
              return;

            this._parent.finishAuthorizationRequest();
            this._parent.onAuthorizationReceived(aURL);
          },
          onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {
            const wpl = Ci.nsIWebProgressListener;
            if (aStateFlags & (wpl.STATE_START | wpl.STATE_IS_NETWORK))
              this._checkForRedirect(aRequest.name);
          },
          onLocationChange: function(aWebProgress, aRequest, aLocation) {
            this._checkForRedirect(aLocation.spec);
          },
          onProgressChange: function() {},
          onStatusChange: function() {},
          onSecurityChange: function() {},

          window: aWindow,
          webProgress: aWebProgress,
          _parent: this.account
        };
        aWebProgress.addProgressListener(this._listener,
                                         Ci.nsIWebProgress.NOTIFY_ALL);
      },
      QueryInterface: XPCOMUtils.generateQI([Ci.prplIRequestBrowser])
    };
    Services.obs.notifyObservers(this._browserRequest, "browser-request", null);
  },
  finishAuthorizationRequest: function() {
    // Clean up the cookies, so that several twitter OAuth dialogs can work
    // during the same session (bug 954308).
    let cookies = Services.cookies.getCookiesFromHost("twitter.com");
    while (cookies.hasMoreElements()) {
      let cookie = cookies.getNext().QueryInterface(Ci.nsICookie2);
      Services.cookies.remove(cookie.host, cookie.name, cookie.path, false);
    }

    if (!("_browserRequest" in this))
      return;
    this._browserRequest._active = false;
    if ("_listener" in this._browserRequest)
      this._browserRequest._listener._cleanUp();
    delete this._browserRequest;
  },
  onAuthorizationReceived: function(aData) {
    let data = this._parseURLData(aData.split("?")[1]);
    if (data.oauth_token != this.token || !data.oauth_verifier) {
      this.gotDisconnected(Ci.prplIAccount.ERROR_OTHER_ERROR,
                           _("connection.error.authFailed"));
      return;
    }
    this.requestAccessToken(data.oauth_verifier);
  },
  requestAccessToken: function(aTokenVerifier) {
    this.reportConnecting(_("connection.requestAccess"));
    this.signAndSend("oauth/access_token", null, [],
                     this.onAccessTokenReceived, this.onError, this,
                     [["oauth_verifier", aTokenVerifier]]);
  },
  onAccessTokenReceived: function(aData) {
    this.LOG("Received access token.");
    let result = this._parseURLData(aData);
    if (!this.fixAccountName(result))
      return;

    let prefValue = {};
    try {
      JSON.parse(this.prefs.getCharPref("oauth"));
    } catch(e) { }
    prefValue[this.consumerKey] = result;
    this.prefs.setCharPref("oauth", JSON.stringify(prefValue));

    this.token = result.oauth_token;
    this.tokenSecret = result.oauth_token_secret;

    this.getTimelines();
  },
  fixAccountName: function(aAuthResult) {
    if (!aAuthResult.screen_name || aAuthResult.screen_name == this.name)
      return true;

    if (aAuthResult.screen_name.toLowerCase() != this.name.toLowerCase()) {
      this.onError(_("connection.error.userMismatch"));
      return false;
    }

    this.LOG("Fixing the case of the account name: " +
             this.name + " -> " + aAuthResult.screen_name);
    this.__defineGetter__("name", function() aAuthResult.screen_name);
    return true;
  },

  cleanUp: function() {
    this.finishAuthorizationRequest();
    if (this._pendingRequests.length != 0) {
      for each (let request in this._pendingRequests)
        request.abort();
      delete this._pendingRequests;
    }
    if (this._streamTimeout) {
      clearTimeout(this._streamTimeout);
      delete this._streamTimeout;
      // Remove the preference observer that is added when the user stream is
      // opened. (This needs to be removed even if an error occurs, in which
      // case _streamingRequest is immediately deleted.)
      this.prefs.removeObserver("track", this);
    }
    if (this._streamingRequest) {
      this._streamingRequest.abort();
      delete this._streamingRequest;
    }
    delete this._pendingData;
    delete this.token;
    delete this.tokenSecret;
  },
  gotDisconnected: function(aError, aErrorMessage) {
    if (this.disconnected || this.disconnecting)
      return;

    if (aError === undefined)
      aError = Ci.prplIAccount.NO_ERROR;
    let connected = this.connected;
    this.reportDisconnecting(aError, aErrorMessage);
    this.cleanUp();
    if (this._timeline && connected)
      this._timeline.notifyObservers(this._timeline, "update-conv-chatleft");
    this.reportDisconnected();
  },
  remove: function() {
    if (!this._timeline)
      return;
    this._timeline.close();
    delete this._timeline;
  },
  unInit: function() {
    this.cleanUp();
  },
  disconnect: function() {
    this.gotDisconnected();
  },

  onError: function(aException) {
    if (aException == "offline") {
      this.gotDisconnected(Ci.prplIAccount.ERROR_NETWORK_ERROR,
                           _("connection.error.noNetwork"));
    }
    else
      this.gotDisconnected(Ci.prplIAccount.ERROR_OTHER_ERROR, aException.toString());
  },
};
Account.prototype.__proto__ = GenericAccountPrototype;

function meliProtocol() { }
meliProtocol.prototype = {
  get normalizedName() "meli",
  get name() "MercadoLibre",
  get iconBaseURI() "chrome://prpl-meli/skin/",
  get noPassword() true,
  options: {
    "sites": {label: "Sites",  default: "MLV",
             listValues: {"MLA": "Argentina",
                          "MLB": "Brasil",
                          "MCO": "Colombia",
                          "MCR": "Costa Rica",
                          "MEC": "Ecuador",
                          "MLC": "Chile",
                          "MLM": "Mexico",
                          "MLU": "Uruguay",
                          "MLV": "Venezuela",
                          "MPA": "Panam\xE1",
                          "MPE": "Per\xFA",
                          "MPT": "Portugal",
                          "MRD": "Dominicana"}}
  },
  getAccount: function(aImAccount) new Account(this, aImAccount),
  classID: Components.ID("{9f8dcea5-3816-43aa-94ca-32dedb715f3e}"),
};
meliProtocol.prototype.__proto__ = GenericProtocolPrototype;

const NSGetFactory = XPCOMUtils.generateNSGetFactory([meliProtocol]);
