Java.perform(function() {
    var Map = Java.use('java.util.Map');
    var UnityWebRequest = Java.use('com.unity3d.player.UnityWebRequest');
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
