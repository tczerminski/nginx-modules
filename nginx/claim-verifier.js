// noinspection JSUnresolvedFunction,JSCheckFunctionSignatures,JSUnresolvedVariable,JSUnusedGlobalSymbols

function jwt(data) {
    const parts = data.split('.').slice(0, 2)
        .map(v => Buffer.from(v, 'base64url').toString())
        .map(JSON.parse);
    return {headers: parts[0], payload: parts[1]};
}

function verify(r) {
    r.log("Verifying request: " + JSON.stringify(r));
    r.subrequest("/validate", function (reply) {
        r.log("/validate reply received: " + JSON.stringify(reply));
        if (reply.status >= 200 && reply.status < 300) {
            const username = jwt(/VouchCookie=(?<token>.+?\..+?\..+?)($|\s+?)/i.exec(r.headersIn.Cookie).groups.token).payload.username;
            if (username === process.env.REQUIRED_USERNAME) {
                r.status = 204;
                r.sendHeader();
                r.finish();
            } else {
                r.return(403)
            }
        } else {
            r.return(401)
        }
    })
    r.return(401)
}

export default {verify}
