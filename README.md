### learn-frida-the-hard-way

TODOs: 
- Add GIFs & docs
- SQLite hook example (+Native)


`
Interceptor.attach(Module.findExportByName('libsqlite.so', 'sqlite3_prepare16_v2'), {
  onEnter: function(args) {
     console.log('DB: ' +  Memory.readUtf16String(args[0]) + '\tSQL: ' + Memory.readUtf16String(args[1]));
  }
});
`



* Hook example: `java.lang.reflect.Method#invoke(Object obj, Object... args, boolean bool)`

        Java.use('java.lang.reflect.Method').invoke.overload('java.lang.Object', '[Ljava.lang.Object;', 'boolean').implementation = function(a,b,c) {
            console.log('hooked!', a, b, c);
            return this.invoke(a,b,c);
        };


* Hook constructor

        Java.use('java.lang.StringBuilder').$init.overload('java.lang.String').implementation = function(stringArgument) {
            console.log("c'tor");
            return this(stringArgument);
        };

