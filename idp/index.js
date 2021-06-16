const config = require('config')
const express = require('express')
const { generators } = require('openid-client');
const authBasic = require('basic-auth');
const bcrypt = require('bcrypt');
const {redirect_to, validUrl} = require("../utils");

const db = require('../db');

const jwt = require('jsonwebtoken')
const JSONWebKey = require('json-web-key' )

const HOST = config.myhost;

function idpRoutes({redisClient, webKeyPub, webKeyPrivate}) {

    const router = express.Router();
    router.get("/certs", (req, res) => {
        res.json({keys: [
            JSONWebKey.fromPEM(webKeyPub).toJSON()
        ]});
    });

    router.get("/auth", async (req, res) => {
        let { scope, redirect_uri, response_type, client_id, state, nonce} = req.query;
        
        if (!response_type || response_type != "code") {
            /* See https://tools.ietf.org/html/rfc6749#section-4.1.2.1 :
            If the request fails due to a missing, invalid, or mismatching
            redirection URI, or if the client identifier is missing or invalid,
            the authorization server SHOULD inform the resource owner of the
            error and MUST NOT automatically redirect the user-agent to the
            invalid redirection URI.
            */
            res.status(400).render('idp_error', { user: null, error: "Invalid 'response_type'" });
            return;
        }

        // Check client_id
        // Client ids are actually UUIDs so first we check format:
        client_id = client_id || '';
        if (!client_id.match(/[\da-fA-F]{8}\-[\da-fA-F]{4}\-[\da-fA-F]{4}\-[\da-fA-F]{4}\-[\da-fA-F]{12}/))
        {
            // Same rationale as above (See https://tools.ietf.org/html/rfc6749#section-4.1.2.1):
            res.status(400).render('idp_error', { user: null, error: "Invalid 'client_id'" });
            return;
        }

        redirect_uri = redirect_uri || '';
        if (! validUrl(redirect_uri))
        {
            // Same rationale as above (See https://tools.ietf.org/html/rfc6749#section-4.1.2.1):
            res.status(400).render('idp_error', { user: null, error: `Invalid 'redirect_uri' : '${redirect_uri}'` });
            return;
        }

        // And then we check (and retrieve) the client registration info
        // based on their id:
        let client_registration;
        try {
            let {rows} = await db.query("SELECT * FROM clients WHERE active IS TRUE AND id=$1 AND redirect_uri=$2",
                                        [client_id, redirect_uri]);

            if (!rows || rows.length == 0) {
                // Same rationale as above (See https://tools.ietf.org/html/rfc6749#section-4.1.2.1):
                res.status(400).render('idp_error', { user: null, error: `No client registration for client: '${client_id}' and redirect URI: '${redirect_uri}'` });
                return;
            }
            client_registration = rows[0];
        }
        catch (e) {
            console.log("%O", e);
            res.status(500).send("Database error!!");
            return;
        }
        
        if (!client_registration || client_registration.redirect_uri != redirect_uri) {
            
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
            
            const data = { uid: req.session.profile.uid, scope, redirect_uri, client_id, nonce,
                           secret_hash: client_registration.pwd_hash};
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
        
        // Redis 6.2 supports getdel (https://redis.io/commands/getdel) ..
        // anyway..
        await redisClient.del('oidc-code:' + code);

        // Check clients credentials (secret):
        // See https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
        const authHeader = req.get("Authorization")
        const creds = authBasic.parse(authHeader);
        if (!creds || ! await bcrypt.compare(creds.pass, authReq.secret_hash)) {
            console.log("Client credentials not valid! Authorization header:"+authHeader);
            // Error response: https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
            res.status(400).json({error: "invalid_request"});
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


    router.get("/userinfo", async (req, res) => {
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
    return router;
}

module.exports = idpRoutes;