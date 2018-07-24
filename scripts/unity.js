// bytes 2 hex 2 string
function b2h2s(array, n) {
    var result = '';
    for (var i = 0, l = n ? n: 100; i < l; ++i) {
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    }
    // hex 2 string
    // TODO extract facebookID from previous_winners packet
    var string = '';
    for (var i = 0; i < result.length; i += 2) {
      string += String.fromCharCode(parseInt(result.substr(i, 2), 16));
    }
    return string;
}

Java.perform(function() {

    Java.use('java.io.InputStream').read.overload('[B').implementation = function(b) {
        var retval = this.read(b);
        var resp = b2h2s(b);
        // conditions to not print garbage packets
        if (resp.indexOf('isBot') == -1 && resp.indexOf(' Answer') == -1 && resp.indexOf('Pinged') == -1) {
            console.log( resp );
        }
        if (resp.indexOf('Waiting To Show Question') != -1) {
            console.log("******************************\n");
            console.log( b2h2s( b , 1200) );
            console.log("\n******************************");
        }
        // TODO mimic answer packet (hook OutputStream), send to get back the answer
        return retval;
    };

});

/*
{"status":"Success","gameState":"Waiting To Show Question","questionIndex":0,"gameID":"5b575b2bd3bff
******************************



{"status":"Success","gameState":"Waiting To Show Question","questionIndex":0,"gameID":"5b575b2bd3bff500048c6e91","player1":{"_id":"5b5617b69e848a00044765df","name":"test","facebookID":"","botImage":null,"points":3490,"characterIndex":0,"accuracy":71.54500693523188,"crowns":7},"player2":{"_id":"5a1d866a700dd2000431659d","name":"Zion A","facebookID":"","botImage":"https://s3-eu-west-1.amazonaws.com/data.dbrain.co.il/lhjkaf61mc81/questions/gar/group2/Zion A.jpg","points":13910,"characterIndex":-1,"accuracy":75,"crowns":3007}}



{"status":"Success","gameState":"Waiting For One Answer","lastQuestionIndex":-1}

{"status":"Success","gameState":"Waiting For One Answer","lastQuestionIndex":-1}

{"status":"Success","secondsSinceOtherUserPinged":0.184}

{"status":"Success","gameState":"Waiting For One Answer","lastQuestionIndex":-1}
OK


{"status":"Success","gameState":"Waiting For One Answer","lastQuestionIndex":-1}

{"status":"Success","gameState":"Waiting To Show Question","lastQuestionIndex":0,"lastQuestion":{"qu
******************************



{"status":"Success","secondsSinceOtherUserPinged":0.536}

{"status":"Success","gameState":"Waiting To Show Question","lastQuestionIndex":0,"lastQuestion":{"questionID":"sport_0000000348","question":"ÃÂÃÂÃÂ ÃÂ¡ÃÂÃÂÃÂ ÃÂÃÂªÃÂÃÂÃÂÃÂ§ÃÂ ÃÂ©ÃÂÃÂ ÃÂÃÂ ÃÂÃÂ© ÃÂÃÂÃÂ¨ÃÂÃÂÃÂªÃÂÃÂÃÂ?","answer":3,"answerFromPlayer1":3,"accuracyFromPlayer1":100,"answerFromPlayer2":3,"accuracyFromPlayer2":100,"answerForBotValue":3,"answerForBotTime":10,"secondsTookToAnswerPlayer1":7.131}}


{"status":"Success","gameState":"Waiting To Show Question","lastQuestionIndex":1,"lastQuestion":{"qu
******************************



{"status":"Error: Trying to answer wrong question"}

{"status":"Success","gameState":"Waiting To Show Question","lastQuestionIndex":1,"lastQuestion":{"questionID":"israeli_music_0000000015","question":"ÃÂÃÂÃÂ§ÃÂª ÃÂ¨ÃÂÃÂ§ ÃÂÃÂ©ÃÂ¨ÃÂÃÂÃÂÃÂª: ÃÂ§ÃÂ¨ÃÂ _","answer":9,"answerFromPlayer1":9,"accuracyFromPlayer1":100,"answerFromPlayer2":9,"accuracyFromPlayer2":100,"answerForBotValue":9,"answerForBotTime":7,"secondsTookToAnswerPlayer1":5.98}}

*/
/*
    Java.use('java.nio.ByteBuffer').wrap.overload('[B').implementation = function(byteArr) {
        console.log('*', byteArr.toString());
        console.log('**', Object.getOwnPropertyNames(byteArr.__proto__).join('\n\t'));
        return this.wrap(byteArr);
    };
        console.log(hexdump(Memory.readByteArray(ptr(buf1.$handle), 32), {offset: 0, length: 32, header: true, ansi: true}));
            buf3: buf1.asCharBuffer().toString(),
            np: Memory.readByteArray(ptr(buf1.$handle), 64),
            retval: retval,

    var Map = Java.use('java.util.Map');
    var UnityWebRequest = Java.use('com.unity3d.player.UnityWebRequest');

    UnityWebRequest.downloadCallback.overload('java.nio.ByteBuffer', 'int').implementation = function(buf1, int2) {
        var retval = this.downloadCallback(buf1, int2);
        console.log('downloadCallback', JSON.stringify({
            buf1: buf1.toString(),
            int2: int2
        }, null, '  '));
        return retval;
    };


    var bClass = Java.use("java.io.OutputStream");
    bClass.write.overload('int').implementation = function(x) {
        console.log("[1] " + x);
        return this.write(x);
    }
    bClass.write.overload('[B').implementation = function(b) {
        console.log("[2] " + hex2string( bytes2hex( b ) ) );
        return this.write(b);
    }
    bClass.write.overload('[B','int','int').implementation = function(b,y,z) {
        console.log("[3] " + hex2string( bytes2hex( b ) ) + " | " + y + " | " + z);
        return this.write(b,y,z);
    }
    var ReadableByteChannel = Java.use('java.nio.channels.ReadableByteChannel');
    ReadableByteChannel.read.overload('java.nio.ByteBuffer').implementation = function(b) {
        console.log('arg1', b);
        var retval = this.read(b);
        console.log('retval', retval);
        return retval;
    };


    UnityWebRequest.headerCallback.overload('java.util.Map').implementation = function(map1) {
        console.log('headerCallback', Java.cast(map1, Map).toString());
        this.headerCallback(map1);
    };
    UnityWebRequest.headerCallback.overload('java.lang.String', 'java.lang.String').implementation = function(s1, s2) {
        console.log('headerCallback', s1, s2);
        this.headerCallback(s1, s2);
    };
    UnityWebRequest.uploadCallback.overload('java.nio.ByteBuffer').implementation = function(buf1) {
        console.log('uploadCallback', buf1);
        this.uploadCallback(buf1);
    };

    Java.use('javax.net.ssl.HttpsURLConnection')['setSSLSocketFactory'].overload('javax.net.ssl.SSLSocketFactory').implementation = function(s) {
        console.log('invoked!', s);
        return this.setSSLSocketFactory(null);
    };
    Java.use('javax.net.ssl.SSLContext')['init']
    .overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
    .implementation = function(a1, a2, a3) {
        console.log('invoked!', a1, a2, a3);
        return this.init(null, null, null);
    };
*/























function bytes2hex(array) {
    var result = '';
//    console.log('len = ' + array.length);
    for (var i = 0; i < array.length; ++i) {
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    }
    return result;
}

function hex2string(hex) {
    var string = '';
    for (var i = 0; i < hex.length; i += 2) {
      string += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return string;
}

Java.perform(function() {
//    var Map = Java.use('java.util.Map');
//    var UnityWebRequest = Java.use('com.unity3d.player.UnityWebRequest');
//
//    UnityWebRequest.downloadCallback.overload('java.nio.ByteBuffer', 'int').implementation = function(buf1, int2) {
//        var retval = this.downloadCallback(buf1, int2);
//        console.log('downloadCallback', JSON.stringify({
//            buf1: buf1.toString(),
//            int2: int2
//        }, null, '  '));
//        return retval;
//    };

    var bClass = Java.use("java.io.OutputStream");
    bClass.write.overload('int').implementation = function(x) {
        console.log("[1] " + x);
        return this.write(x);
    }
    bClass.write.overload('[B').implementation = function(b) {
        console.log("[2] " + hex2string( bytes2hex( b ) ) );
        return this.write(b);
    }
    bClass.write.overload('[B','int','int').implementation = function(b,y,z) {
        console.log("[2] " + hex2string( bytes2hex( b ) ) + " | " + y + " | " + z);
        return this.write(b,y,z);
    }

});



Java.perform(function() {
    var Map = Java.use('java.util.Map');
    var UnityWebRequest = Java.use('com.unity3d.player.UnityWebRequest');
	console.log( Object.getOwnPropertyNames(Test.__proto__).join('\n') );

    /*
        UnityWebRequest.$init
            .overload('long', 'java.lang.String', 'java.util.Map', 'java.lang.String', 'int').implementation = function(long1, str2, map3, str4, int5) {
                console.log(this, JSON.stringify({
                    '#1': long1,
                    method: str2,
                    headers: Java.cast(map3, Map).toString(),
                    url: str4,
                    '#5': int5
                }, null, '  '));
                this.$init(long1, str2, map3, str4, int5);
            };
        Java.use('com.unity3d.player.WWW').$init.overload('int', 'java.lang.String', '[B', 'java.util.Map').implementation = function(int1, str2, bytes3, map4) {
            console.log(this, JSON.stringify({
                '#1': int1,
                str2: str2,
                bytes3: bytes3,
                map4: Java.cast(map4, Map).toString()
            }, null, '  '));
        };            
    */
    UnityWebRequest.headerCallback.overload('java.util.Map').implementation = function(map1) {
        console.log('headerCallback', Java.cast(map1, Map).toString());
        this.headerCallback(map1);
    };
    var Str = Java.use('java.lang.String');
    // var decoder = Java.use('java.nio.charset.Charset').forName("UTF-8");
    UnityWebRequest.downloadCallback.overload('java.nio.ByteBuffer', 'int').implementation = function(byteBuffer1, int2) {
        console.log('downloadCallback', JSON.stringify({
            byteBuffer1: byteBuffer1.toString(),
            int2: int2
        }, null, '  '));
//	Java.perform(function(){ console.log('--', Java.cast(byteBuffer1, Java.use('java.lang.String'))); });
        return this.downloadCallback(byteBuffer1, int2);
    };
});
/*
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        // console.log("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.indexOf("epsi") != -1) {
            console.log(
		this.lib.substr(this.lib.lastIndexOf('/') + 1, this.lib.length) + 
		' [ ' + retval + ' ] \n' + 
		Module.enumerateExportsSync(this.lib).map(function(x){return x.name}) 
            );  
        }
    }
});
*/
