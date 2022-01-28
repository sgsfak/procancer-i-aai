const config = require('config')
const express = require('express')
const { generators } = require('openid-client');
const authBasic = require('basic-auth');
const bcrypt = require('bcrypt');
const ulid = require('ulid');
const {redirect_to, validUrl} = require("../utils");

const db = require('../db');

const jwt = require('jsonwebtoken')
const JSONWebKey = require('json-web-key' );

const HOST = config.myhost;
const CONFID_CLIENTS_TTL = config.confidential_clients_ttl || 3600;

function idpRoutes({redisClient, webKeyPub, webKeyPrivate}) {

    const newAccessToken = function(subject, audience, ttl, authorized_party, scope="read write") {

        const accToken = {type: "access_token", azp: authorized_party, scope};
        const token = jwt.sign(accToken, webKeyPrivate, {
            jwtid: ulid.ulid(),
            algorithm: 'RS256', expiresIn: ttl,
            issuer: HOST, audience, subject
        });
        return token;
    }

    const getUser = async function(user_id) {
        let user_data = null;
        let error = null;
        try {
            const {rows} = await db.query("select * from users where user_id=$1",
                                        [user_id]);
            if (rows && rows.length != 0) {
                user_data = rows[0];
                Object.keys(user_data).forEach(key => {
                    if (user_data[key] === null) {
                      delete user_data[key];
                    }
                });
            }
        }
        catch (e) {
            console.log("%O", e);
            error = e;
        }
        return [error, user_data];
    }


    const db_client_registration = async function(client_id) {
        // Check client_id, and retrieve the client registration info
        // based on this:
        let client_registration = null;
        let error = null;
        try {
            let {rows} = await db.query("SELECT * FROM clients WHERE active IS TRUE AND id=$1",
                                        [client_id]);
            if (rows && rows.length != 0) {
                client_registration = rows[0];
            }
        }
        catch (e) {
            console.log("%O", e);
            error = e;
        }
        // Golang conventions:
        return [client_registration, error];
    }

    const router = express.Router();
    router.get("/certs", (req, res) => {
        let jwk = JSONWebKey.fromPEM(webKeyPub).toJSON();
        // Add some additional claims for the signing key
        // As an example, see https://www.googleapis.com/oauth2/v3/certs
        /* 
        use: this claim specifies the intended use of the key. 
             There are two possible uses: sig (for signature) and enc (for encryption). 
             This claim is optional. 
             The same key can be used for encryption and signatures, 
             in which case this member should not be present.
        */
        jwk.use = "sig";
        /*
        alg: The algorithm intended to be used with this key.
             We use RS256: RSASSA PKCS1 v1.5 using SHA-256
        */
        jwk.alg = "RS256";
        /*
        x5u: a URL that points to a X.509 public key certificate or certificate chain 
             in PEM encoded form.
        */
        jwk.x5u = `${HOST}${req.baseUrl}/pem`;
        res.json({keys: [jwk]});
    });


    router.get("/pem", async (req, res) => {
        res.type("txt").send(webKeyPub);
    });

    router.get("/auth", async (req, res) => {
        let { scope, redirect_uri, response_type, client_id, state, nonce, audience, code_challenge} = req.query;
        

        // Make sure we have values for these params:
        response_type = response_type || '';
        client_id = client_id || '';
        audience = audience || client_id; // The access token will have the 'aud' claim

        // Check client_id, and retrieve the client registration info
        // based on this:
        let [client_registration, error] = await db_client_registration(client_id);
        if (error) {
            console.log("%O", e);
            res.status(500).send("Database error!!");
            return;
        }
        if (!client_registration) {
            /* See https://tools.ietf.org/html/rfc6749#section-4.1.2.1 :
            If the request fails due to a missing, invalid, or mismatching
            redirection URI, or if the client identifier is missing or invalid,
            the authorization server SHOULD inform the resource owner of the
            error and MUST NOT automatically redirect the user-agent to the
            invalid redirection URI.
            */
            res.status(400).render('idp_error', { user: null, error: `No active client registration for id: '${client_id}'` });
            return;    
        }

        // Check that client has sent the correct redirect uri:
        // (use by default the one already registered)
        redirect_uri = redirect_uri || client_registration.redirect_uri;
        if (client_registration.redirect_uri != redirect_uri)
        {
            // Same rationale as above (See https://tools.ietf.org/html/rfc6749#section-4.1.2.1):
            res.status(400).render('idp_error', { user: null, error: `Invalid 'redirect_uri' : '${redirect_uri}'` });
            return;
        }
        

        const requestedResponseTypes = response_type.trim().split(/\s+/);

        if (! requestedResponseTypes.includes("code")) {
            // See https://tools.ietf.org/html/rfc6749#section-4.1.2.1
            // for error responses
            redirect_to(res, redirect_uri, {
                error: "unsupported_response_type",
                description: "This server supports only the authorization code flow (for now)",
                state
            });
            return;
        }

        response_type = requestedResponseTypes.includes("code") ? "code" : "token";

        if (!!req.session.profile) {
            const code = generators.random();
            console.log("Active session: %O", req.session.profile);
            
            const data = { uid: req.session.profile.uid, scope, redirect_uri, client_id, nonce,
                           code_challenge, audience, secret_hash: client_registration.pwd_hash};
            const code_ttl = 2 * 60; // 2 minutes TTL for this code
            await redisClient.set('oidc-code:' + code, JSON.stringify(data), 'ex', code_ttl);
            redirect_to(res, redirect_uri, {code, state});
            return;
        }
        else {
            const r = new URL(`${HOST}${req.baseUrl}/auth`);
            for (const [k, v] of Object.entries(req.query)) {
                r.searchParams.append(k, v);
            }
            req.session.continue = r.toString();
            console.log("Not active session: redirecting to login, and then to %s", r);
            res.redirect(302, `${HOST}/login`);
        }
    });

    router.post("/token", async (req, res) => {
        // See https://developer.okta.com/docs/reference/api/oidc/#token
        let {code, redirect_uri, grant_type, client_id, client_secret, code_verifier, audience, refresh_token} = req.body;

        // Get clients supplied credentials:
        // See https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
        // We first check the 'Authorization' header:
        const authHeader = req.get("Authorization")
        if (authHeader) {
            // If there's an Authorization header it overrides any client-* information
            // passed in the form-encoded body
            const creds = authBasic.parse(authHeader);
            client_secret = creds ? creds.pass : '';
            client_id = creds ? creds.name : '';
        }
        // If no such header, we use the secret supplied in the params
        // or an empty string:
        else {
            client_secret = client_secret || '';
        }

        const TTL = 30 * 60; // Access token lifetime: 30 minutes
        const REFRESH_TTL = 24 * 60 * 60; // Refresh token lifetime: 24 hours

        if (grant_type == "client_credentials") {
            // Check client_id, and retrieve the client registration info
            // based on this:
            let [client_registration, error] = await db_client_registration(client_id);
            if (error) {
                console.log("%O", e);
                res.status(500).send("Database error!!");
                return;
            }

            // Check clients credentials (secret):
            if (!client_registration || ! await bcrypt.compare(client_secret, client_registration.pwd_hash)) {
                console.log("Client credentials not valid! Authorization header:"+authHeader);
                res.status(400).json({error: "invalid_request"});
                return;
            }
            
            const scope = req.body.scope || 'access';
            const jwtAccToken = newAccessToken(client_id, audience || client_id, CONFID_CLIENTS_TTL, client_id, scope);
            let response = {token_type : "Bearer", expires_in : CONFID_CLIENTS_TTL, 
                            access_token: jwtAccToken};
            console.log("CliCreds Token response: %O", response);
            res.json(response);
            return;
        }
        else if (grant_type == "authorization_code") {
            const authReqStored = await redisClient.get('oidc-code:' + code);
            if (!authReqStored) {
                res.status(401).json({error: 'invalid_grant'});
                return;
            }
            // Redis 6.2 supports getdel (https://redis.io/commands/getdel) ..
            // anyway..
            await redisClient.del('oidc-code:' + code);

            const authReq = JSON.parse(authReqStored);
            if (!redirect_uri || authReq.redirect_uri != redirect_uri) {
                res.status(401).json({error: 'invalid_grant'});
                return;
            }
            // Check Authorization Code flow with PKCE 
            // See https://datatracker.ietf.org/doc/html/rfc7636#section-4.6 
            if (authReq.code_challenge) {
                code_verifier = code_verifier || '';
                if (generators.codeChallenge(code_verifier) != authReq.code_challenge) {
                    res.status(401).json({ error: 'invalid_grant', error_description: 'S256 code_verifier is not correct' });
                    return;
                }
            }
            
            // Check clients credentials (secret):
            if (! await bcrypt.compare(client_secret, authReq.secret_hash)) {
                console.log("Client credentials not valid! Authorization header:"+authHeader);
                // Error response: https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
                res.status(400).json({error: "invalid_request"});
                return;
            }


            let [error, user_data] = await getUser(authReq.uid);
            if (error || !user_data) {console.log("Client credentials not valid! Authorization header:"+authHeader);
                // Error response: https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
                res.status(500).json({error: error ? error : 'User not found'});
                return;
            }

            delete user_data['elixir_id_token'];
            user_data['sub'] = user_data['uid'] = authReq.uid;

            let idToken = user_data; // JSON.parse(await redisClient.get("uid:"+authReq.uid));
            idToken.type = "id_token";
            idToken.nonce = authReq.nonce;
            
            const jwtIdToken = jwt.sign(idToken, webKeyPrivate, {
                algorithm: 'RS256', expiresIn: TTL,
                issuer: HOST, audience: authReq.client_id
            });
            
            const jwtAccToken = newAccessToken(idToken.uid, authReq.audience, TTL, authReq.client_id, authReq.scope);
            const refreshToken = generators.random(32);
            const refreshTokenInfo = {
                uid: idToken.uid,
                audience: authReq.audience,
                scope: authReq.scope,
                client_id: authReq.client_id,
                d: Date.now(),
                g: 0
            }
            let response = {token_type : "Bearer", expires_in : TTL, 
                            nonce: authReq.nonce,
                            scope: authReq.scope,
                            id_token: jwtIdToken, access_token: jwtAccToken, refresh_token: refreshToken};
            await redisClient.set('tokens:refresh:'+refreshToken, JSON.stringify(refreshTokenInfo), 'ex', REFRESH_TTL);
            console.log("Token response: %O", response);
            res.json(response);
            return;
        }
        else if (grant_type == "refresh_token") {
            // Check client_id, and retrieve the client registration info
            // based on this:
            let [client_registration, error] = await db_client_registration(client_id);
            if (error) {
                console.log("%O", e);
                res.status(500).send("Database error!!");
                return;
            }

            // Check clients credentials (secret):
            if (!client_registration || ! await bcrypt.compare(client_secret, client_registration.pwd_hash)) {
                console.log("Client credentials not valid! Authorization header:"+authHeader);
                res.status(400).json({error: "invalid_request"});
                return;
            }

            // Retrieve refresh token info
            let refreshTokenInfo = JSON.parse(await redisClient.get("tokens:refresh:"+refresh_token));
            if (!refreshTokenInfo || client_id != refreshTokenInfo.client_id) {
                res.status(400).json({error: "invalid_request"});
                return;
            }
            await redisClient.del("tokens:refresh:"+refresh_token)
            if (client_id != refreshTokenInfo.client_id) {
                res.status(400).json({error: "invalid_request"});
                return;
            }
            refreshTokenInfo.scope = req.body.scope || refreshTokenInfo.scope;
            refreshTokenInfo.g += 1;
            const jwtAccToken = newAccessToken(refreshTokenInfo.uid, refreshTokenInfo.audience, TTL, client_id, refreshTokenInfo.scope);
            const refreshToken = generators.random(32);
            let response = {token_type : "Bearer", expires_in : TTL, 
                            scope: refreshTokenInfo.scope,
                            access_token: jwtAccToken, refresh_token: refreshToken};
            await redisClient.set('tokens:refresh:'+refreshToken, JSON.stringify(refreshTokenInfo), 'ex', REFRESH_TTL);
            console.log("Refresh Token response: %O", response);
            res.json(response);
            return;
        }

        // Only "authorization_code", "client_credentials", and "refresh_token" are supported:
        res.status(401).json({error: 'unsupported_grant_type'});
        return;
    });


    router.get("/userinfo", async (req, res) => {
        const authHeader = req.header("Authorization") || '';
        jwtToken = authHeader.replace("Bearer", "").trim();
        try {
            const token = jwt.verify(jwtToken, webKeyPub);
            const uid = token.uid || token.sub;
            // let a = await redisClient.get("uid:"+uid);
            let [error, a] = getUser(uid);
            if (error) {
                res.status(500).json(JSON.parse({error}));
                return;
            }
            res.json(JSON.parse(a));
        }
        catch(error) {
            res.status(400).json({error});
        }
    });

    return { newAccessToken, router };
}

module.exports = idpRoutes;

