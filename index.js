const config = require('config')
const { Issuer, generators, custom } = require('openid-client');
const session = require('express-session')
const express = require('express')
const multer = require("multer")()
const fs = require('fs');
const Redis = require('ioredis')

const {redirect_to} = require("./utils");
const db = require('./db');
const ulid = require('ulid');

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


// See how-to-create-RS256-keys.txt
const webKeyPub = fs.readFileSync('jwtRS256.key.pub');
const webKeyPrivate = fs.readFileSync('jwtRS256.key');

app.use(session({
    name: "aai-sid",
    unset: "destroy",
    secret: generators.random(),
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
// Test the connection to the database, and the existence of the clients table:
.then (() =>  db.query("SELECT count(redirect_uri) cnt FROM clients where active is true"))
.then (({rows}) => console.log(`Number of available clients:${rows[0].cnt}`))
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

const findOrInsertUser = async function(elixirUid, idToken) {
    const userId = ulid.ulid();
    const {rows} = await db.query("INSERT INTO users(user_id, elixir_id, elixir_id_token) VALUES($1,$2,$3) ON CONFLICT (elixir_id) DO UPDATE SET elixir_id_token=EXCLUDED.elixir_id_token RETURNING *",
                                  [userId, elixirUid, idToken]);
    const user_data = rows[0];
    Object.keys(user_data).forEach(key => {
        if (user_data[key] === null) {
          delete user_data[key];
        }
    });
    return user_data;
}

app.get('/oidcb', async (req, res) => {
    const params = client.callbackParams(req);
    console.log("got cb");
    console.dir(params);
    
    const code_verifier = req.session.code_verifier;
    const nonce = req.session.nonce;
    
    try {
        const tokenSet = await client.callback(`${HOST}/oidcb`, params, { code_verifier, state: params.state, nonce});
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());
        req.session.tokens = tokenSet;
        req.session.user = tokenSet.claims();
        const access_token = tokenSet.access_token;
        const userInfo = await client.userinfo(access_token);

        console.log("%O", userInfo);

        req.session.profile = await findOrInsertUser(userInfo.sub, userInfo);
        req.session.profile.uid = req.session.profile.user_id; // XXX
        console.log("User %s logged in", req.session.profile.uid);

        // await redisClient.set("uid:" + userInfo.uid, JSON.stringify(userInfo));
        
        if (req.session.continue) {
            const u = req.session.continue;
            delete req.session.continue;
            redirect_to(res, u);
        }
        else {
            res.redirect("/profile");
        }
    }
    catch (e) {
        console.log(e);
        let u = "/";
        if (req.session.continue) {
            u = req.session.continue;
            delete req.session.continue;
        }
        res.redirect(u);
    }
});


function routeAuth(req, res, next) {
    if (!!req.session.profile) {
        next();
    }
    else {
        res.redirect("/login");
    }
}


app.get('/profile', routeAuth, (req, res) => {
    view(req, res, 'profile', {profile: req.session.profile});
});

app.get("/logout", (req, res)=>{
    // TODO: Actually in the case of https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    // we should check if the post_logout_redirect_uri value supplied match 
    // one of the client's previously registered post_logout_redirect_uris values.

    // TODO: Furthermore "An id_token_hint carring an ID Token for the RP is also REQUIRED 
    // when requesting post-logout redirection; if it is not supplied with post_logout_redirect_uri,
    // the OP MUST NOT perform post-logout redirection." 
    let { post_logout_redirect_uri, state} = req.query;
    req.session.destroy();
    if (post_logout_redirect_uri) {
        redirect_to(res, post_logout_redirect_uri, {state});
    }
    else {
        res.redirect("/");
    }
});


app.get("/.well-known/openid-configuration", (req, res) => {
    
    const configuration = {
        response_types_supported: [ "code" ],
        introspection_endpoint: `${HOST}/oauth2/introspect`,
        grant_types_supported: ["authorization_code", "client_credentials", "refresh_token"],
        issuer: `${HOST}`,
        introspection_endpoint_auth_methods_supported: "none",
        response_modes_supported: ["query"],
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
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: [ "S256" ],
        
        // See: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
        token_endpoint_auth_methods_supported: [ "client_secret_basic", "client_secret_post"],
        
        authorization_endpoint: `${HOST}/oauth2/auth`,
        userinfo_endpoint: `${HOST}/oauth2/userinfo`,
        end_session_endpoint: `${HOST}/logout`,
        token_endpoint: `${HOST}/oauth2/token`,
        jwks_uri: `${HOST}/oauth2/certs`
    };
    res.json(configuration);
});

app.get("/doregister", (req, res)=> {
    redirect_to(res, "https://perun.elixir-czech.cz/registrar/", {
        vo: 'elixir',
        targetnew: `${HOST}/login`,
        targetexisting: `${HOST}/login`});
});


app.get("/me", routeAuth, (req, res) => {
    res.json(req.session.profile);
});



app.get('/users', routeAuth, async (req, res) => {
    try {
        let {rows} = await db.query(
            `SELECT user_id uid, elixir_id sub, user_verified,
            name, email, email_verified, user_verified
            FROM users`
            );
        return res.json(rows);
    }
    catch (e) {
        console.log(e);
        res.status(500).send("Internal database error");
    }
});

app.get('/organizations', routeAuth, async (req, res) => {
    try {
        let {rows} = await db.query("SELECT id, name, full_name, country FROM organizations ORDER BY id ASC");
        return res.json(rows);
    }
    catch (e) {
        console.log(e);
        res.status(500).send("Internal database error");
    }
});

const { newAccessToken, router : oauthRouter } = require("./idp")({redisClient, webKeyPub, webKeyPrivate});


app.get("/access_token", routeAuth, (req, res) => {
    view(req, res, 'access_token', {});
});

app.post("/access_token", routeAuth, multer.none(), (req, res) => {
    let { audience, ttl, scopes } = req.body;
    audience = audience || HOST;
    ttl = (ttl || 1) * 60 * 60;
    scopes = scopes || "read write";
    const token = newAccessToken(req.session.profile.uid, audience, ttl, `${HOST}`, scopes);
    res.set('Cache-Control', 'no-store'); // No cache
    res.type('txt').send(token);
});


app.use("/oauth2", oauthRouter);
