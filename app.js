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

dotenv.load();

var usersaml;

passport.serializeUser(function (user, done) {
    usersaml = {};
    usersaml.nameID = user['issuer']['_'];
    usersaml.nameIDFormat = user['issuer']['$'];
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

var CALLBACK_URL = "https://authenticationtest492.herokuapp.com/login/callback";
var ENTRY_POINT = "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO";
var ISSUER = "localhost";

var LOGOUT_URL = "https://www.testshib.org/Shibboleth.sso/Logout";
var LOGOUT_CALLBACK_URL = "https://authenticationtest492.herokuapp.com/logout/callback";

/* TODO: figure out how to ask for only specific attributes

    Possibly something akin to the following?

passport.use(samlStrategy,
    function (profile, done) {
        return done(null,
            {
                id: profile.uid,
                email: profile.email,
                displayName: profile.cn,
                firstName: profile.givenName,
                lastName: profile.sn
            });
    });

    */

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
    return done(null, profile);
});

/*
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
    decryptionPvk: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
    // Service Provider Certificate
    privateCert: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
    // Identity Provider's public key
    cert: fs.readFileSync(__dirname + '/cert/idp_cert.pem', 'utf8'),
    validateInResponseTo: false,
    disableRequestedAuthnContext: true,
    forceAuthn: true,
    additionalParams: {}
}, function (profile, done) {
    return done(null, profile);
});*/

passport.use(samlStrategy);

var app = express();

app.use(express.static('public'));
app.use(cookieParser());
app.use(bodyParser());
app.use(session({ secret: "secret" }));
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    else {
        samlStrategy['Redirect'] = req['route']['path'];
        return res.redirect('/login');
    }
}

var homePage = fs.readFileSync('public/home.html').toString();
app.get('/',
    function (req, res) {
        res.writeHead(200, {
            'Content-Type': 'text/html'
        });

        res.end(homePage);
    }
);

var securePage = fs.readFileSync('public/secure.html').toString();
app.get('/secure',
    ensureAuthenticated, function (req, res) {
        res.writeHead(200, {
            'Content-Type': 'text/html'
        });

        res.end(securePage);
    }
);

app.get('/login',
    passport.authenticate('saml', { failureRedirect: '/login/fail' }),
    function (req, res) {
        res.redirect('/');
    }
);

app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/login/fail' }),
    function (req, res) {
        /*
            User information in: req["user"]
        
         */
        //console.log(req["user"]);
        var redirect = samlStrategy['Redirect'];
        console.log(redirect);
        res.redirect(redirect);
    }
);

app.get('/login/fail',
    function (req, res) {
        res.status(401).send('Login failed');
    }
);

app.get('/Metadata',
    function (req, res) {
        res.type('application/xml');
        res.status(200).send(samlStrategy.generateServiceProviderMetadata(process.env.CERT));
    }
);

app.get('/Session',
    function (req, res) {
        res.send(req.user);
    }
);

/* TODO: redirect back to homePage?? */
// ComplexLogout
// Redirects to IdP logout
passport.logoutSaml = function (req, res) {
    if (usersaml != null) {
        req.user.nameID = usersaml.nameID;
        req.user.nameIDFormat = usersaml.nameIDFormat;

        samlStrategy.logout(req, function (err, request) {
            if (!err) {
                //redirect to the IdP Logout URL
                req.session.destroy(function () {
                    req.logout();
                });
                res.redirect(request);
            }
        });
    }
};

passport.logoutSamlCallback = function (req, res) {
    res.redirect('/');
}

app.post('/logout/callback', function (req, res) {
    console.log("** In /logout/callback");
    res.redirect('/');
});

app.get('/logout', function (req, res) {
    passport.logoutSaml(req, res);
    //simpleLogout(req, res);
});

function simpleLogout(req, res) {
    req.logout();
    req.session.destroy(function (err) {
        res.clearCookie('connect.sid');
        res.redirect('/'); //Inside a callback… bulletproof!
    });
};

//general error handler
app.use(function (err, req, res, next) {
    console.log("Fatal error: " + JSON.stringify(err));
    next(err);
});

var port = process.env.PORT || 8000;
var server = app.listen(port, function () {
    console.log('Listening on port %d', server.address().port)
});

//Masters