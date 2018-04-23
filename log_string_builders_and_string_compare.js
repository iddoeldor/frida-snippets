Java.perform(function() {
    // string compare
    var str = Java.use('java.lang.String'), objectClass = 'java.lang.Object';
    str.equals.overload(objectClass).implementation = function(obj) {
        var response = str.equals.overload(objectClass).call(this, obj);
        if (obj) {
            if (obj.toString().length > 5) {
                send(str.toString.call(this) + ' == ' + obj.toString() + ' ? ' + response);
            }
        }
        return response;
    }
    // log AbstractStringBuilder.toString()
    ['java.lang.StringBuilder', 'java.lang.StringBuffer'].forEach(function(clazz, i) {
        console.log('[?] ' + i + ' = ' + clazz);
        var func = 'toString';
        Java.use(clazz)[func].implementation = function() {
            var ret = this[func]();
            send('[' + i + '] ' + ret);
            return ret;
        };
    });    
});
