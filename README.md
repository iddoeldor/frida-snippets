# Contents
 - [Enumerate loaded classes](#enumerate-loaded-classes) 
 - [Extract modules from APK](#extract-modules-from-apk) 
 - [Get methods from .so file](#get-methods-from-so-file)
 - [SQLite hook example](#sqlite-hook-example)
 - [Hook Java refelaction](#hook-refelaction)
 - [Hook constructor](#hook-constructor)
 
 
#### Enumerate loaded classes
```
$ frida -U com.pkg -qe 'Java.perform(function(){Java.enumerateLoadedClasses({"onMatch":function(c){console.log(c);}});});' -o pkg.classes
```
#### Extract modules from APK
```
  $ frida -Uq com.android. -e "Process.enumerateModules({onMatch: function(m){console.log('-' + m.name)},onComplete:function(){}})"
  ....
  -libsqlite.so
```

#### Get methods from so file
```
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
 ```        
#### SQLite hook
```
Interceptor.attach(Module.findExportByName('libsqlite.so', 'sqlite3_prepare16_v2'), {
      onEnter: function(args) {
          console.log('DB: ' + Memory.readUtf16String(args[0]) + '\tSQL: ' + Memory.readUtf16String(args[1]));
      }
});
```

#### Hook refelaction: 
`java.lang.reflect.Method#invoke(Object obj, Object... args, boolean bool)`
```
  Java.use('java.lang.reflect.Method').invoke.overload('java.lang.Object', '[Ljava.lang.Object;', 'boolean').implementation = function(a,b,c) {
      console.log('hooked!', a, b, c);
      return this.invoke(a,b,c);
  };
```

#### Hook constructor
```
Java.use('java.lang.StringBuilder').$init.overload('java.lang.String').implementation = function(stringArgument) {
      console.log("c'tor");
      return this(stringArgument);
};
```
* Hook Native (JNI)
```
var moduleName = "libfoo.so"; 
var nativeFuncAddr = 0x1234; // $ nm --demangle --dynamic libfoo.so | grep "Class::method("

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        console.log("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.endsWith(moduleName)) {
            console.log("ret: " + retval);
            var baseAddr = Module.findBaseAddress(moduleName);
            Interceptor.attach(baseAddr.add(nativeFuncAddr), {
                onEnter: function(args) {
                    console.log("[-] hook invoked");
                    console.log(JSON.stringify({
                        a1: args[1].toInt32(),
                        a2: Memory.readUtf8String(Memory.readPointer(args[2])),
                        a3: Boolean(args[3])
                    }, null, '\t'));
                }
            });
        }
    }
});
```
* Print all runtime strings & stacktrace
```
Java.perform(function() {
  ['java.lang.StringBuilder', 'java.lang.StringBuffer'].forEach(function(clazz, i) {
    console.log('[?] ' + i + ' = ' + clazz);
    var func = 'toString';
    Java.use(clazz)[func].implementation = function() {
      var ret = this[func]();
      send('[' + i + '] ' + ret);
      // raising an exception to get stacktrace
      Java.perform(function() {
        send('[*] ' + Java.use('java.lang.Exception').$new().getStackTrace().toString().split(',')[1]);
      });
    }
    return ret;
  };
});
```

* (iOS) Extract UUID for specific path when attached to an app
```
var PLACEHOLDER = '{UUID}';
function extractUUIDfromPath(path) {
    var bundleIdentifier = String(ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_('CFBundleIdentifier'));
    var path_prefix = path.substr(0, path.indexOf(PLACEHOLDER));
    var plist_metadata = '/.com.apple.mobile_container_manager.metadata.plist';
    var folders = ObjC.classes.NSFileManager.defaultManager().contentsOfDirectoryAtPath_error_(path_prefix, NULL);
    for (var i = 0, l = folders.count(); i < l; i++) {
        var uuid = folders.objectAtIndex_(i);
        var metadata = path_prefix + uuid + plist_metadata;
        var dict = ObjC.classes.NSMutableDictionary.alloc().initWithContentsOfFile_(metadata);
        var enumerator = dict.keyEnumerator();
        var key;
        while ((key = enumerator.nextObject()) !== null) {
            if (key == 'MCMMetadataIdentifier') {
                var appId = String(dict.objectForKey_(key));
                if (appId.indexOf(bundleIdentifier) != -1) {
                    return path.replace(PLACEHOLDER, uuid);
                }
            }
        }
    }
}
console.log( extractUUIDfromPath('/var/mobile/Containers/Data/Application/' + PLACEHOLDER + '/Documents') );
```
TODOs: 
- Add GIFs & docs

References overview:

* https://techblog.mediaservice.net/2017/09/tracing-arbitrary-methods-and-function-calls-on-android-and-ios/
* https://zhiwei.li/text/2016/02/01/%E7%BC%96%E8%AF%91frida/
* https://kov4l3nko.github.io/blog/2018-05-27-sll-pinning-hook-sectrustevaluate/
