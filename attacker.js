function start(args, proxy, ua, secondcookies){

    args.target = args.target.replace(/%RAND%/g, Math.random().toString(36).substring(7)); // lol
    if(!(args.postdata == false)) args.postdata = args.postdata.replace(/%RAND%/g, Math.random().toString(36).substring(7)); // lol

    if(args.mode == 'http') require('./http.js')(args, proxy, ua, secondcookies);
    if(args.mode == 'http2') require('./http2.js')(args, proxy, ua, secondcookies);
    if(args.mode == 'httptest') require('./httptest.js')(args, proxy, ua, secondcookies);
    if(args.mode == 'socket') require('./socket.js')(args, proxy, ua, secondcookies);
	if(args.mode == 'sockettest') require('./sockettest.js')(args, proxy, ua, secondcookies);
}

module.exports = start;