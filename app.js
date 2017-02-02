var http = require('http');
var fs = require('fs');
var express = require("express");
var dotenv = require('dotenv');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var saml = require('passport-saml');
var Mustache = require('mustache');

//var PiwikTracker = require('piwik-tracker');

var baseUrl = 'https://authenticationtest492.herokuapp.com';
//var piwik = new PiwikTracker(1, baseUrl + "/piwik.php");
/*
piwik.track({
    url: baseUrl + "/piwik",
    action_name: 'Action name',
    res: true
},
console.log);
*/

//var piwik = require('piwik').setup(baseUrl + "/piwik");

/*
var piwik = require('piwik').setup("http://localhost:8000");

piwik.api(
    {
        method: 'Actions.getPageUrls',
        period: 'day',
        date: 'today'
    },
    function (err, data) {
        console.log(err);
        //console.log(data);
    }
);
/*piwik.track({
    url: baseUrl,
    action_name: 'Test Action',
    ua: 'Node.js v0.10.24',
    cvar: JSON.stringify({
        '1': ['name', 'value']
    })
});*/

dotenv.load();


/*
    TODO: try SAML2-js??
    https://github.com/Clever/saml2
 */

passport.serializeUser(function (user, done) {
    /*
    usersaml = {};
    usersaml.nameID = user['issuer']['_'];
    usersaml.nameIDFormat = user['issuer']['$'];
*/
    //console.log("SERIALIZE: " + user['issuer']['_'] +": " + user['issuer']['$']);

    done(null, user);
});

// user.sessionID

passport.deserializeUser(function (user, done) {
    done(null, user);
});

var CALLBACK_URL = baseUrl + "/login/callback";
var ENTRY_POINT = "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO";
var ISSUER = "localhost";


// chained url here?
var LOGOUT_URL = "https://www.testshib.org/Shibboleth.sso/Logout";
//var LOGOUT_URL = "https://authenticationtest492.herokuapp.com/logout?return=https://www.testshib.org/Shibboleth.sso/Logout";
var LOGOUT_CALLBACK_URL = baseUrl + "/logout/callback";

var samlStrategy = new saml.Strategy({
    // URL that goes from the Identity Provider -> Service Provider
    callbackUrl: CALLBACK_URL,
    // URL that goes from the Service Provider -> Identity Provider
    entryPoint: ENTRY_POINT,
    // Usually specified as `/shibboleth` from site root
    issuer: ISSUER,
    logoutUrl: LOGOUT_URL,
    logoutCallbackUrl: LOGOUT_CALLBACK_URL,
    identifierFormat: null,
    // Service Provider private key
    decryptionPvk: process.env.KEY,
    // Service Provider Certificate
    privateCert: process.env.KEY,
    // Identity Provider's public key
    cert: fs.readFileSync(__dirname + '/cert/idp_cert.pem', 'utf8'),
    validateInResponseTo: false,
    disableRequestedAuthnContext: true,
    forceAuthn: true,
    isPassive: false,
    additionalParams: {}
}, function (profile, done) {
    usersaml = {};
    usersaml.nameID = profile['issuer']['_'];
    usersaml.nameIDFormat = profile['issuer']['$'];
    return done(null, profile);
});

passport.use(samlStrategy);

var app = express();

app.use(express.static('public'));
app.use(cookieParser());
app.use(bodyParser());
app.use(session({ secret: "secret" }));
app.use(passport.initialize());
app.use(passport.session());

/*
app.get('/piwik', function (req, res) {
    //var tracker = piwik.getTracker('https://authenticationtest492.herokuapp.com', 1);
    console.log("In app.get");
    res.send("hello");
});

app.post('/piwik', function (req, res) {
    console.log("In app.post");
})

*/
var parameters = {
    'app': app,
    'Mustache': Mustache,
    'fs': fs,
    'passport': passport,
    'samlStrategy': samlStrategy
}
    app.get('/logout', function (req, res) {
        passport.logoutSaml(req, res);
    })


    passport.logoutSaml = function (req, res) {
        if (usersaml != null) {
            //Here add the nameID and nameIDFormat to the user if you stored it someplace.
            req.user = {};
            req.user.nameID = usersaml.nameID;
            req.user.nameIDFormat = usersaml.nameIDFormat;

            //console.log("ID: " + usersaml.nameID + "; Format: " + usersaml.nameIDFormat);

            samlStrategy.logout(req, function (err, request) {
                if (!err) {
                    //redirect to the IdP Logout URL
                    console.log("Redirecting to " + request);
                    req.session.destroy(function (err) {
                        res.clearCookie('sid');
                        req.logout();
                        res.redirect(request);
                    });
                    /*
                    req.session.destroy();
                    res.clearCookie("connect.sid");
                    res.redirect(request);
                    */
                }
            });
        }
    }

require('./public/routes.js')(parameters);

var port = process.env.PORT || 8000;
var server = app.listen(port, function () {
    console.log('Listening on port %d', server.address().port);
});

