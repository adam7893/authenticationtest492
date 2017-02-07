module.exports = function (parameters) {
    var app = parameters['app'];
    var Mustache = parameters['Mustache'];
    var fs = parameters['fs'];
    var passport = parameters['passport'];
    var samlStrategy = parameters['samlStrategy'];

    var usersaml;

    function ensureAuthenticated(req, res, next) {
        //console.log(req.user != null)
        if (req.isAuthenticated() && (req.user != null)) {
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

        if (req.isAuthenticated() && (req.user != null)) {
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

        /*for (var key in req) {
            console.log();
        }*/

        //console.log(req['cookies']);

        /*fs.writeFile("req.txt", req.toString(), function(err) {
            if (err) {
                return console.log(err);
            }
            console.log("success");
        })*/
        //console.log(req);
        //console.log(res);

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
        passport.authenticate('saml', { session: true, failureRedirect: '/login/fail' }),
        function (req, res) {
            //console.log("***login req: " + req);
            //console.log("***login res: " + res);
            res.redirect('/');
        }
    );

    app.post('/login/callback',
        passport.authenticate('saml', { session: true, failureRedirect: '/login/fail' }),
        function (req, res) {
            //console.log("**********callback req: " + req);
            //console.log("**********callback res: " + res);

            //console.log("*****callback req cookies: " + req['cookies']['connect.sid']);
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
        res.send(req.user != null);
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


    app.get('/Shibboleth.sso/logout', function (req, res) {
        console.log("in shibboleth/logout...");
        res.redirect('/');
    });



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
}