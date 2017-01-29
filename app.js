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
    /*usersaml = {};
    usersaml.nameID = user['issuer']['_'];
    usersaml.nameIDFormat = user['issuer']['$'];*/

    done(null, user);
});

// user.sessionID

passport.deserializeUser(function (user, done) {
    done(null, user);
});

var CALLBACK_URL = "https://authenticationtest492.herokuapp.com/login/callback";
var ENTRY_POINT = "https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO";
var ISSUER = "localhost";


// chained url here?
var LOGOUT_URL = "https://www.testshib.org/Shibboleth.sso/Logout";
//var LOGOUT_URL = "https://authenticationtest492.herokuapp.com/logout?return=https://www.testshib.org/Shibboleth.sso/Logout";
var LOGOUT_CALLBACK_URL = "https://authenticationtest492.herokuapp.com/logout/callback";

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
    usersaml.nameID = profile.nameID;
    usersaml.nameIDFormat = profile.nameIDFormat;
    //return done(null, profile);
});

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
app.get('/', function (req, res) {
    res.writeHead(200, {
        'Content-Type': 'text/html'
    });

    var list = [];
    var partialPage;
    /*var dummyUser = "John Doe";
    var testBool = false;*/

    if (req.isAuthenticated()) {
        // User is logged in
        list = [{ user: req.user["urn:oid:0.9.2342.19200300.100.1.1"] }];
        partialPage = fs.readFileSync('public/authenticated.html').toString();
    }
    else {
        partialPage = fs.readFileSync('public/notAuthenticated.html').toString();
        list = [{ user: null }];
    }

    var html = Mustache.render(homePage, {
        list: list
    }, {
            partial: partialPage
        });

    res.end(html);
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

        /*
        var redirect = samlStrategy['Redirect'];
        res.redirect(redirect);
        */

        res.redirect('/');  //changed just for ease of testing
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
        //res.status(200).send(samlStrategy.generateServiceProviderMetadata(process.env.CERT));
        res.status(200).send(samlStrategy.generateServiceProviderMetadata(fs.readFileSync(__dirname + '/cert/idp_cert.pem', 'utf8')));
    }
);

app.get('/User', function (req, res) {
    res.send(req.user);
});

app.get('/Session', function (req, res) {
    res.send(req.session);
});

app.get('/body', function (req, res) {
    res.send(req.body);
});

app.get('/cookies', function (req, res) {
    res.send(req.cookies);
})

//general error handler
app.use(function (err, req, res, next) {
    console.log("Fatal error: " + JSON.stringify(err));
    next(err);
});

/*
    req.logout()
    res.clearCookie('connect.sid')
    req.session.destroy()
    res.redirect(' <idp.logout>');
        "https://www.testshib.org/Shibboleth.sso/Logout"
 */

app.post("/logout", function (req, res) {
    if (req.body["cookies"]) {
        console.log("Clearing cookies");
        res.clearCookie("connect.sid");
    }

    if (req.body["destroy"]) {
        console.log("Destroying");
        req.session.destroy();
    }

    if (req.body["logout"]) {
        console.log("Logging out");
        req.logout();
    }

    if (req.body["idp"]) {
        console.log("Redirecting to IdP logout");
        passport.logoutSaml(req, res);
    }
    else {
        console.log("Redirecting to home page");
        res.redirect("/");
    }
});

app.get('/logout', function (req, res) {
    passport.logoutSaml(req, res);
})

app.get('/Shibboleth.sso/logout', function (req, res) {
    console.log("in shibboleth/logout...");
    res.redirect('/');
});

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

passport.logoutSamlCallback = function (req, res) {
    console.log("In SamlCallback")
    res.redirect('/');
}

app.post('/logout/callback', passport.logoutSamlCallback);

app.get('/logout/callback', function (req, res) {
    console.log("In logout/callback");
    req.logout();
    res.redirect('/');
})

/*
app.get("/logout", function (req, res) {
    passport.logoutSaml(req, res);
});

passport.logoutSamlCallback = function (req, res) {
    req.logout();
    res.redirect('/');
}

app.post('/logout/callback', passport.logoutSamlCallback);

passport.logoutSaml = function (req, res) {
    if (usersaml != null) {
        console.log("Within usersaml != null");
        //Here add the nameID and nameIDFormat to the user if you stored it someplace.
        req.user = {};
        req.user.nameID = usersaml.nameID;
        req.user.nameIDFormat = usersaml.nameIDFormat;

        samlStrategy.logout(req, function (err, request) {
            if (!err) {
                //redirect to the IdP Logout URL
                res.redirect(request);
            }
        });
    }
};*/

var port = process.env.PORT || 8000;
var server = app.listen(port, function () {
    console.log('Listening on port %d', server.address().port);
});

