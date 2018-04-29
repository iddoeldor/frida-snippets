### learn-frida-the-hard-way

TODOs: 
- Add GIFs & docs

- Extract modules from APK

        $ frida -Uq com.android. -e "Process.enumerateModules({onMatch: function(m){console.log('-' + m.name)},onComplete:function(){}})"
        ....
        -libsqlite.so
        
- get methods from .so file
        $ adb pull /system/lib/libsqlite.so
         /system/lib/libsqlite.so: 1 file pulled. 19.7 MB/s (975019 bytes in 0.047s)
        $ nm -D libsqlite.so | cut -d' ' -f3 | grep sqlite3
        sqlite3_aggregate_context
        sqlite3_aggregate_count
        ....
        
        $ frida-trace -U -i "sqlite*" com.android.
        ...
         24878 ms  sqlite3_changes()
         24878 ms  sqlite3_reset()
         24878 ms     | sqlite3_free()
         24878 ms     | sqlite3_free()
         24878 ms  sqlite3_clear_bindings()
         24878 ms  sqlite3_prepare16_v2()  <<< this is the one that holds the SQL queries
         24878 ms     | sqlite3_free()
         
- SQLite hook example (+Native)

        Interceptor.attach(Module.findExportByName('libsqlite.so', 'sqlite3_prepare16_v2'), {
            onEnter: function(args) {
                console.log('DB: ' + Memory.readUtf16String(args[0]) + '\tSQL: ' + Memory.readUtf16String(args[1]));
            }
        });




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

