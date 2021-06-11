const config = require('config')
const { Issuer, generators, custom } = require('openid-client');
const session = require('express-session')
const express = require('express')
const querystring = require('querystring')

const Redis = require('ioredis')
const jwt = require('jsonwebtoken')
const JSONWebKey = require('json-web-key' )
const fs = require('fs');

// See how-to-create-RS256-keys.txt
const webKeyPub = fs.readFileSync('jwtRS256.key.pub');
const webKeyPrivate = fs.readFileSync('jwtRS256.key');

let RedisStore = require('connect-redis')(session)
let redisClient = new Redis({keyPrefix: 'pca-aai:'});

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


app.use(session({
    name: "aai-sid",
    unset: "destroy",
    secret: "ProCance-I AAI", // generators.random(),
    resave: false, saveUninitialized: true,
    store: new RedisStore({ client: redisClient })
}));

app.use(express.urlencoded({extended: true})); 

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


function redirect_to(res, redirect_uri, params={}, status=302) {
    
    const u = new URL(redirect_uri);
    const p = u.searchParams;
    for (const [k, val] of Object.entries(params)) {
        if (!!val) {
            p.append(k, val);
        }
    }

    console.log("Redirect to %s", u);
    res.redirect(status, u.toString());
}


app.get('/', (req, res) => {
    view(req, res, 'home');
});


app.get('/login', (req, res) => {

    // XXX
    if (req.session.continue) {
        const userInfo = { uid:"ssfak@ics.forth.gr", first_name: "Stelios", last_name: "Sfakianakis", email:"ssfak@ics.forth.gr" };
        redisClient.set("uid:"+userInfo.uid, JSON.stringify(userInfo));
        req.session.profile = userInfo;
        const u = req.session.continue;
        delete req.session.continue;
        redirect_to(res, u);
        return;
    }

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
        redisClient.set("uid:"+userInfo.uid, JSON.stringify(userInfo));
        res.redirect("/profile");
    })
    .catch(e => {
        console.log(e);
        let u = "/";
        if (req.session.continue) {
            u = req.session.continue;
            delete req.session.continue;
        }
        res.redirect(u);
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


app.get("/.well-known/openid-configuration", (req, res) => {

    const configuration = {
        response_types_supported: [ "code", "token"],
        introspection_endpoint: `${HOST}/oauth2/introspect`,
        grant_types_supported: [
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "authorization_code"
        ],
        issuer: `${HOST}`,
        introspection_endpoint_auth_methods_supported: "none",
        claims_supported: [
                "iss",
                "sub",
                "aud",
                "iat",
                "exp",
                "jti",
                "name",
                "first_name",
                "family_name",
                "email"
        ],
        subject_types_supported: [ "public"],
        id_token_signing_alg_values_supported: [ "RS256" ],
        token_endpoint_auth_methods_supported: [ "none", "private_key_jwt"],
        authorization_endpoint: `${HOST}/oauth2/auth`,
        userinfo_endpoint: `${HOST}/userinfo`,
        token_endpoint: `${HOST}/oauth2/token`,
        jwks_uri: `${HOST}/oauth2/certs`
    };
    res.json(configuration);
});

app.get("/doregister", (req, res)=> {
    redirect_to(res, "https://perun.elixir-czech.cz/registrar/",
                                {  vo: 'elixir_test', 
                                   targetnew: `${HOST}/login`,
                                   targetexisting: `${HOST}/login`});
});


app.get("/me", (req, res) => {
    res.json(req.session.profile);
});

app.get("/oauth2/certs", (req, res) => {
    res.json({keys: [
        JSONWebKey.fromPEM(webKeyPub).toJSON()
    ]});
});
    
app.get("/oauth2/auth", (req, res) => {
    let { scope, redirect_uri, response_type, client_id, state, nonce} = req.query;

    if (!redirect_uri ) {
        res.status(400).json({ error: "invalid_request" });
        return;
    }

    if (response_type != "code" || !response_type || !client_id) {

        // See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
        // for error responses
        redirect_to(res, redirect_uri, {
            error: "unsupported_response_type",
            description: "This server supports only the authorization code flow",
            state
        });
        return;
    }

    if (!!req.session.profile) {
        const code = generators.random();
        console.log("Active session: %O", req.session.profile);

        const data = { uid: req.session.profile.uid, scope, redirect_uri, client_id, nonce};
        redisClient.set('oidc-code:' + code, JSON.stringify(data));
        redirect_to(res, redirect_uri, {code, state});
        return;
    }
    else {
        const r = new URL(`${HOST}${req.path}`);
        for (const [k,v] of Object.entries(req.query))
            r.searchParams.append(k, v);
        req.session.continue = r.toString();
        console.log("Not active session: redirecting to login, and then to %s", r);
        res.redirect(302, `${HOST}/login`);
    }
});

app.post("/oauth2/token", async (req, res) => {
    // See https://developer.okta.com/docs/reference/api/oidc/#token
    const {code, redirect_uri, grant_type, client_id} = req.body;
    if (grant_type != "authorization_code" ) {
        res.status(401).json({error: 'unsupported_grant_type'});
        return;
    }
    const authReqStored = await redisClient.get('oidc-code:' + code);
    if (!authReqStored) {
        res.status(401).json({error: 'invalid_grant'});
        return;
    }
    const authReq = JSON.parse(authReqStored);
    if (!redirect_uri || authReq.redirect_uri != redirect_uri) {
        res.status(401).json({error: 'invalid_grant'});
        return;
    }

    let idToken = JSON.parse(await redisClient.get("uid:"+authReq.uid));
    idToken.iss = HOST;
    idToken.type = "id_token";
    idToken.aud = authReq.client_id;
    idToken.nonce = authReq.nonce;

    const TTL = 3600;
    const jwtIdToken = jwt.sign(idToken, webKeyPrivate, {algorithm: 'RS256', expiresIn: TTL});

    const accToken = {iss: HOST, type: "access_token", aud: client_id, uid: idToken.uid};
    const jwtAccToken = jwt.sign(accToken, webKeyPrivate, {algorithm: 'RS256', expiresIn: TTL});

    let response = {token_type : "Bearer", expires_in : TTL, 
                    nonce: authReq.nonce,
                    scope: authReq.scope,
                    id_token: jwtIdToken, access_token: jwtAccToken};
    console.log("Token response: %O", response);
    res.json(response);
});


app.get("/userinfo", async (req, res) => {
    const authHeader = req.header("Authorization") || '';
    jwtToken = authHeader.replace("Bearer", "").trim();
    try {
        const token = jwt.verify(jwtToken, webKeyPub);
        let a = await redisClient.get("uid:"+token.uid);
        res.json(JSON.parse(a));
    }
    catch(error) {
        res.status(400).json({error});
    }
});
