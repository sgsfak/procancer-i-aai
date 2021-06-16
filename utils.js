const URL = require("url").URL;

function validUrl(s) {
    try {
        new URL(s);
        return true;
    } catch (err) {
        return false;
    }
};



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


module.exports = {redirect_to, validUrl}