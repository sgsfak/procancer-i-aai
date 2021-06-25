const config = require('config')
const express = require('express')
const { generators } = require('openid-client');
const authBasic = require('basic-auth');
const bcrypt = require('bcrypt');
const {redirect_to, validUrl} = require("../utils");

const db = require('../db');

const jwt = require('jsonwebtoken')
const JSONWebKey = require('json-web-key' );

const HOST = config.myhost;

function idpRoutes({redisClient, webKeyPub, webKeyPrivate}) {

    const newAccessToken = function(subject, audience, ttl, scope="read write") {

        const accToken = {type: "access_token", scope};
        const token = jwt.sign(accToken, webKeyPrivate, {
            algorithm: 'RS256', expiresIn: ttl,
            issuer: HOST, audience, subject
        });
        return token;
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
        let client_registration;
        try {
            let {rows} = await db.query("SELECT * FROM clients WHERE active IS TRUE AND id=$1",
                                        [client_id]);

            if (!rows || rows.length == 0) {

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
            client_registration = rows[0];
        }
        catch (e) {
            console.log("%O", e);
            res.status(500).send("Database error!!");
            return;
        }

        // Check that client has sent the correct redirect uri:
        redirect_uri = redirect_uri || '';
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
        let {code, redirect_uri, grant_type, client_id, client_secret, code_verifier} = req.body;
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
        // Check Authorization Code flow with PKCE 
        // See https://datatracker.ietf.org/doc/html/rfc7636#section-4.6 
        if (authReq.code_challenge) {
            code_verifier = code_verifier || '';
            if (generators.codeChallenge(code_verifier) != authReq.code_challenge) {
                res.status(401).json({ error: 'invalid_grant', error_description: 'S256 code_verifier is not correct' });
                return;
            }
        }
        
        // Redis 6.2 supports getdel (https://redis.io/commands/getdel) ..
        // anyway..
        await redisClient.del('oidc-code:' + code);

        // Check clients credentials (secret):
        // See https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
        // We first check the 'Authorization' header:
        const authHeader = req.get("Authorization")
        if (authHeader) {
            const creds = authBasic.parse(authHeader);
            client_secret = creds ? creds.pass : '';
        }
        // If no such header, we use the secret supplied in the params
        // or an empty string:
        else {
            client_secret = client_secret || '';
        }
        if (! await bcrypt.compare(client_secret, authReq.secret_hash)) {
            console.log("Client credentials not valid! Authorization header:"+authHeader);
            // Error response: https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
            res.status(400).json({error: "invalid_request"});
            return;
        }

        let idToken = JSON.parse(await redisClient.get("uid:"+authReq.uid));
        idToken.type = "id_token";
        idToken.nonce = authReq.nonce;
        
        const TTL = 3600;
        const jwtIdToken = jwt.sign(idToken, webKeyPrivate, {
            algorithm: 'RS256', expiresIn: TTL,
            issuer: HOST, audience: authReq.client_id
        });
        
        const jwtAccToken = newAccessToken(idToken.uid, authReq.audience, TTL);
        let response = {token_type : "Bearer", expires_in : TTL, 
                        nonce: authReq.nonce,
                        scope: authReq.scope,
                        id_token: jwtIdToken, access_token: jwtAccToken};
        console.log("Token response: %O", response);
        res.json(response);
    });


    router.get("/userinfo", async (req, res) => {
        const authHeader = req.header("Authorization") || '';
        jwtToken = authHeader.replace("Bearer", "").trim();
        try {
            const token = jwt.verify(jwtToken, webKeyPub);
            const uid = token.uid || token.sub;
            let a = await redisClient.get("uid:"+uid);
            res.json(JSON.parse(a));
        }
        catch(error) {
            res.status(400).json({error});
        }
    });

    return { newAccessToken, router };
}

module.exports = idpRoutes;