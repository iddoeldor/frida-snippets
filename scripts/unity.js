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
