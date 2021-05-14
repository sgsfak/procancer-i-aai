const config = require('config')
const { Issuer, generators, custom } = require('openid-client');
const session = require('express-session')
const express = require('express')
const querystring = require('querystring')
const app = express()
const port = 3000

const HOST = config.myhost;

custom.setHttpOptionsDefaults({
    timeout: 10000,
    // hooks: {
    //     beforeRequest: [
    //       (options) => {
    //         console.log('--> %s %s', options.method.toUpperCase(), options.url.href);
    //         console.log('--> HEADERS %o', options.headers);
    //         if (options.body) console.log('--> BODY %O', options.body);
    //       },
    //     ],
    //     afterResponse: [
    //       (response) => {
    //         console.log('<-- %i FROM %s %s', response.statusCode, response.request.options.method.toUpperCase(), response.request.options.url.href);
    //         console.log('<-- HEADERS %o', response.headers);
    //         if (response.body) console.log('<-- BODY %O', response.body);
    //         return response;
    //       },
    //     ],
    //   },
});


app.use(session({secret: generators.random(), resave: false, saveUninitialized: false}));


let client;
Issuer.discover('https://login.elixir-czech.org/oidc/')
.then(issuer => {
    console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
    
    client = new issuer.Client({
        client_id: config.get("elixir_aai.client.id"),
        client_secret: config.get("elixir_aai.client.secret"),
        redirect_uris: `${HOST}/oidcb`,
        response_types: ['code'],
        // id_token_signed_response_alg (default "RS256")
        // token_endpoint_auth_method (default "client_secret_basic")
    });
})
.then(() => app.listen(port))
.then(() => console.log(`ProCancer-I AAI listening at http://localhost:${port}`));

app.use('/static', express.static('public', {maxAge: 60000 * 5}));
app.set('view engine', 'blade');

function view(req, res, template, data={})
{
    const dataUser = {'user' : req.session.user ? req.session.user : null, ...data};
    // console.log("Data: %O", dataUser);
    res.render(template, dataUser);
    
}
app.get('/', (req, res) => {
    view(req, res, 'home');
});


app.get('/login', (req, res) => {
    view(req, res, 'login');
});

app.get('/dologin', (req, res) => {
    const code_verifier = generators.codeVerifier();
    // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
    // it should be httpOnly (not readable by javascript) and encrypted.
    req.session.code_verifier = code_verifier;
    
    const code_challenge = generators.codeChallenge(code_verifier);
    
    const scopes = ['openid',
    'email',
    'profile',
    'address',
    'phone',
    'offline_access',
    'perun_api',
    'country',
    'schac_home_organization',
    'eduperson_scoped_affiliation',
    'voperson_external_affiliation',
    'eduperson_entitlement',
    'eduperson_orcid',
    'ga4gh_passport_v1'];

    const nonce = generators.random();
    req.session.nonce = nonce;

    const u = client.authorizationUrl({
        scope: scopes.join(" "),
        resource: `${HOST}/`,
        state: generators.random(),
        nonce: nonce,
        code_challenge,
        code_challenge_method: 'S256',
    });
    // console.log(`Redirecting to URL=${u}`);
    
    res.redirect(u);
});

app.get('/oidcb', (req, res) => {
    const params = client.callbackParams(req);
    console.log("got cb");
    console.dir(params);
    
    const code_verifier = req.session.code_verifier;
    const nonce = req.session.nonce;

    client.callback(`${HOST}/oidcb`, params, { code_verifier, state: params.state, nonce}).
    then(tokenSet => {
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());
        req.session.tokens = tokenSet;
        req.session.user = tokenSet.claims();
        return tokenSet.access_token;
    })
    .then(access_token => {
        return client.userinfo(req.session.tokens.access_token);
    })
    .then(userInfo => {
        console.log("%O", userInfo);
        req.session.profile = userInfo;
        res.redirect("/profile");
    })
    .catch(e => {
        console.log(e);
        res.redirect("/");
    });
});


app.get('/profile', (req, res) => {
    if (!!req.session.profile) {
        view(req, res, 'profile', {profile: req.session.profile});
    }
    else {
        res.redirect("/login");
    }
    
});

app.get("/logout", (req, res)=>{
    req.session.destroy();
    res.redirect("/");
});

app.get("/doregister", (req, res)=> {
    const qs = querystring.stringify({ vo: 'elixir_test', 
                                    targetnew: `${HOST}/login`,
                                    targetexisting: `${HOST}/login`});
    res.redirect("https://perun.elixir-czech.cz/registrar/?"+qs);
});


