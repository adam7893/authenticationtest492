var http = require('http');
var fs = require('fs');
var express = require("express");
var dotenv = require('dotenv');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var saml = require('passport-saml');

dotenv.load();

passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

var CALLBACK_URL = "https://authenticationtest492.herokuapp.com/login/callback";
var ENTRY_POINT = "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO";
var ISSUER = "localhost";

var LOGOUT_URL = "https://www.testshib.org/Shibboleth.sso/Logout";

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
    identifierFormat: null,
    // Service Provider private key
    decryptionPvk: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
    // Service Provider Certificate
    privateCert: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
    // Identity Provider's public key
    cert: fs.readFileSync(__dirname + '/cert/idp_cert.pem', 'utf8'),
    validateInResponseTo: false,
    disableRequestedAuthnContext: true
}, function (profile, done) {

    /*user.saml = {};
    user.saml.nameID = profile.nameID;
    user.saml.nameIDFormat = profile.nameIDFormat;*/
    return done(null, profile);
});

passport.use(samlStrategy);

var app = express();

app.use(cookieParser());
app.use(bodyParser());
app.use(session({ secret: "secret" }));
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        console.log("You are authenticated");
        return next();
    }
    else {
        return res.redirect('/login');
    }
}

app.get('/',
    function (req, res) {
        res.send('Home');
    }
);

app.get('/secure',
    ensureAuthenticated,
    function (req, res) {
        res.send("Authenticated");
    })

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
        console.log(req);
        res.redirect('/');
    }
);

app.get('/login/fail',
    function (req, res) {
        res.status(401).send('Login failed');
    }
);

app.get('/Shibboleth.sso/Metadata',
    function (req, res) {
        res.type('application/xml');
        res.status(200).send(samlStrategy.generateServiceProviderMetadata(fs.readFileSync(__dirname + '/cert/cert.pem', 'utf8')));
    }
);

/* TODO: figure out logout
        Possibly has to do something with cookies?

        This currently doesn't work
*/
/*
app.get('/logout', function (req, res) {
    req.session.destroy(function (err) {
        req.logout();
        res.redirect('/'); //Inside a callback… bulletproof!
    });
});*/

passport.logoutSaml = function (req, res) {
    //Here add the nameID and nameIDFormat to the user if you stored it someplace.
    /*
    req.user.nameID = req.user.saml.nameID;
    req.user.nameIDFormat = req.user.saml.nameIDFormat;
*/

    samlStrategy.logout(req, function (err, request) {
        if (!err) {
            //redirect to the IdP Logout URL
            res.redirect(request);
        }
    });
};

passport.logoutSamlCallback = function (req, res) {
    req.logout();
    res.redirect('/');
}

app.post('/auth/saml/logout/callback', passport.logoutSamlCallback);

app.get('/logout', function (req, res) {
    req.session.destroy(function () {
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
    //strategy is a ref to passport-saml Strategy instance

    /* TODO: check here! */
    /*samlStrategy.logout(req, function(){
        req.logout();
        res.redirect('/');
    });*/
});





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