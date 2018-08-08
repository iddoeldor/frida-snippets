# Contents
 - [Intercept and backtrace low level open](#intercept-and-backtrace-low-level-open)
 - [Enumerate loaded classes](#enumerate-loaded-classes) 
 - [Java class available methods](#java-class-methods)
 - [Dump iOS class hierarchy](#dump-ios-class-hierarchy) 
 - [iOS instance members values](#ios-instance-members-values)
 - [iOS extract cookies](#ios-extract-cookies)
 - [List modules](#list-modules) 
 - [Get methods from .so file](#get-methods-from-so-file)
 - [SQLite hook example](#sqlite-hook)
 - [Hook Java refelaction](#hook-refelaction)
 - [Hook constructor](#hook-constructor)
 - [Hook JNI by address](#hook-jni-by-address)
 - [Print all runtime strings & Stacktrace](#print-runtime-strings)
 - [Find iOS application UUID](#find-ios-application-uuid)
 - [Execute shell command](https://github.com/iddoeldor/frida-snippets/blob/master/scripts/exec_shell_cmd.py)
 - [Observe iOS class](#observe-ios-class)
 - [File access](#file-access)
 - [Webview URLS](#webview-urls)
 - [Await for specific module to load](#await-for-condition)
 - [Android make Toast](#android-make-toast)
 - [Hook java io InputStream](#hook-java-io-inputstream)
 - [TODO list](#todos)

#### Intercept and backtrace low level open
```javascript
Interceptor.attach(Module.findExportByName("/system/lib/libc.so", "open"), {
	onEnter: function(args) {
		// debug only the intended calls
		this.flag = false;
		var filename = Memory.readCString(ptr(args[0]));
		if (filename.indexOf("epsi") != -1)
			this.flag = true;
		if (this.flag)
			console.log("file name [ " + Memory.readCString(ptr(args[0])) +
			    " ]\nBacktrace:" +
			    Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t")
			);
	},
	onLeave: function(retval) {
		if (this.flag) console.warn("\nretval: " + retval);
	}
});
```

#### Enumerate loaded classes
And save to a file
```
$ frida -U com.pkg -qe 'Java.perform(function(){Java.enumerateLoadedClasses({"onMatch":function(c){console.log(c);}});});' -o pkg.classes
```
Search for class
```javascript
Java.enumerateLoadedClasses({
	onMatch: function(aClass) {
		if (aClass.match("/classname/i")) // match a regex with case insensitive flag
			console.log(aClass);
	},
	onComplete: function() {}
});
```

#### Java class methods
```javascript
Object.getOwnPropertyNames(Java.use('com.company.CustomClass').__proto__).join('\n\t')
```

#### Dump iOS class hierarchy
Object.keys(ObjC.classes) will list all available Objective C classes,
but actually this will return all classes loaded in current process, including system frameworks.
If we want something like weak_classdump, to list classes from executable it self only, Objective C runtime already provides such function [objc_copyClassNamesForImage](#https://developer.apple.com/documentation/objectivec/1418485-objc_copyclassnamesforimage?language=objc)
```javascript
var objc_copyClassNamesForImage = new NativeFunction(
    Module.findExportByName(null, 'objc_copyClassNamesForImage'),
    'pointer',
    ['pointer', 'pointer']
);
var free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer']);
var classes = new Array(count);
var p = Memory.alloc(Process.pointerSize);

Memory.writeUInt(p, 0);

var path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String();
var pPath = Memory.allocUtf8String(path);
var pClasses = objc_copyClassNamesForImage(pPath, p);
var count = Memory.readUInt(p);
for (var i = 0; i < count; i++) {
    var pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize));
    classes[i] = Memory.readUtf8String(pClassName);
}

free(pClasses);

var tree = {};
classes.forEach(function(name) {
    var clazz = ObjC.classes[name];
    var chain = [name];
    while (clazz = clazz.$superClass) {
        chain.unshift(clazz.$className);
    }

    var node = tree;
    chain.forEach(function(clazz) {
        node[clazz] = node[clazz] || {};
        node = node[clazz];
    });
});

send(tree);
```

#### iOS instance members values
Print map of members (with values) for each class instance
```javascript
ObjC.choose(ObjC.classes[clazz], {
  onMatch: function (obj) {
    console.log('onMatch: ', obj);
    Object.keys(obj.$ivars).forEach(function(v) {
        console.log('\t', v, '=', obj.$ivars[v]);
    });
  },
  onComplete: function () {
    console.log('onComplete', arguments.length);
  }
});
```

#### iOS extract cookies
```javascript
 var cookieJar = [];
 var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
 for (var i = 0, l = cookies.count(); i < l; i++) {
     var cookie = cookies['- objectAtIndex:'](i);
     cookieJar.push(cookie.Name() + '=' + cookie.Value());
 }
 console.log(cookieJar.join("; "));
```

#### List modules
```
$ frida -Uq com.android. -e "Process.enumerateModules({onMatch: function(m){console.log('-' + m.name)},onComplete:function(){}})"
  ....
  -libsqlite.so
```
```javascript
Process.enumerateModulesSync()
    .filter(function(m){ return m['path'].toLowerCase().indexOf('app') !=-1 ; })
    .forEach(function(m) {
        console.log(JSON.stringify(m, null, '  '));
        // to list exports use Module.enumerateExportsSync(m.name)
    });
```

#### Get methods from so file
```
  $ adb pull /system/lib/libsqlite.so
   /system/lib/libsqlite.so: 1 file pulled. 19.7 MB/s (975019 bytes in 0.047s)
  $ nm -D libsqlite.so | cut -d' ' -f3 | grep sqlite3
  sqlite3_aggregate_context
  sqlite3_aggregate_count
  ....
  $ rabin2 -c objc_mach0_file | head -n10
    0x00f87a2c [0x00008ea0 - 0x0000ddfe] (sz 20318) class 0 GenericModel
    0x00008ea0 method 0      initWithPeerId:atMessageId:allowActions:important:
    0x000090e2 method 1      initWithPeerId:allowActions:messages:atMessageId:
    0x00009214 method 2      dealloc
    0x00009286 method 3      authorPeerForId:
    0x0000940c method 4      _transitionCompleted
    0x000097fc method 5      _loadInitialItemsAtMessageId:
    0x00009990 method 6      _addMessages:
    0x0000a178 method 7      _deleteMessagesWithIds:
    0x0000a592 method 8      _replaceMessagesWithNewMessages:
  ...
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
```javascript
Interceptor.attach(Module.findExportByName('libsqlite.so', 'sqlite3_prepare16_v2'), {
      onEnter: function(args) {
          console.log('DB: ' + Memory.readUtf16String(args[0]) + '\tSQL: ' + Memory.readUtf16String(args[1]));
      }
});
```

#### Hook refelaction: 
`java.lang.reflect.Method#invoke(Object obj, Object... args, boolean bool)`
```javascript
  Java.use('java.lang.reflect.Method').invoke.overload('java.lang.Object', '[Ljava.lang.Object;', 'boolean').implementation = function(a,b,c) {
      console.log('hooked!', a, b, c);
      return this.invoke(a,b,c);
  };
```

#### Hook constructor
```javascript
Java.use('java.lang.StringBuilder').$init.overload('java.lang.String').implementation = function(stringArgument) {
      console.log("c'tor");
      return this(stringArgument);
};
```
#### Hook JNI by address
Hook native method by module name and method address and print arguments
```javascript
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
#### Print runtime strings 
Print created StringBuilder & StringBuffer & Stacktrace
```javascript
Java.perform(function() {
  ['java.lang.StringBuilder', 'java.lang.StringBuffer'].forEach(function(clazz, i) {
    console.log('[?] ' + i + ' = ' + clazz);
    var func = 'toString';
    Java.use(clazz)[func].implementation = function() {
      var ret = this[func]();
      send('[' + i + '] ' + ret);
      // raising an exception to get stacktrace
      Java.perform(function() {
          Java.use('java.lang.Exception').$new().getStackTrace().toString().split(',').forEach(function(l) {
              console.log('\t[*] ' + l);
          });
      });
    }
    return ret;
  };
});
```
#### Find iOS application UUID 
Get UUID for specific path when attached to an app by reading plist file under each app container
```javascript
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

#### Observe iOS class
```javascript
function observeClass(name) {
    var k = ObjC.classes[name];
    k.$ownMethods.forEach(function(m) {
        var impl = k[m].implementation;
        console.log('Observing ' + name + ' ' + m);
        Interceptor.attach(impl, {
            onEnter: function(a) {
                this.log = [];
                this.log.push('(' + a[0] + ',' + Memory.readUtf8String(a[1]) + ') ' + name + ' ' + m);
                if (m.indexOf(':') !== -1) {
                    var params = m.split(':');
                    params[0] = params[0].split(' ')[1];
                    for (var i = 0; i < params.length - 1; i++) {
                        try {
                            this.log.push(params[i] + ': ' + new ObjC.Object(a[2 + i]).toString());
                        } catch (e) {
                            this.log.push(params[i] + ': ' + a[2 + i].toString());
                        }
                    }
                }

                this.log.push(
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress)
                        .join('\n')
                );
            },

            onLeave: function(r) {
                try {
                    this.log.push('RET: ' + new ObjC.Object(r).toString());
                } catch (e) {
                    this.log.push('RET: ' + r.toString());
                }

                console.log(this.log.join('\n') + '\n');
            }
        });
    });
}
```
Outputs:
`observeClass('Someclass$innerClass');
```
Observing Someclass$innerClass - func
Observing Someclass$innerClass - empty

(0x174670040,parameterName) Someclass$innerClass - func
0x10048dd6c libfoo!0x3bdd6c
0x1005a5dd0 libfoo!0x4d5dd0
0x1832151c0 libdispatch.dylib!_dispatch_client_callout
0x183215fb4 libdispatch.dylib!dispatch_once_f
RET: 0xabcdef
```

#### File Access
iOS file access 
```javascript
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        console.log('open' , ObjC.Object(args[2]).toString());
    }
});
```

#### Webview URLS
```javascript
Java.use("android.webkit.WebView").loadUrl.overload("java.lang.String").implementation = function (s) {
    send(s.toString());
    this.loadUrl.overload("java.lang.String").call(this, s);
};
```

#### Await for condition
Await until specific DLL will load in Unity app, can implement hot swap
```javascript
var awaitForCondition = function(callback) {
    var int = setInterval(function() {
        if (Module.findExportByName(null, "mono_get_root_domain")) {
            clearInterval(int);
            callback();
            return;
        }
    }, 0);
}

function hook() {
    Interceptor.attach(Module.findExportByName(null, "mono_assembly_load_from_full"), {
        onEnter: function(args) {
            this._dll = Memory.readUtf8String(ptr(args[1]));
            console.log('[*]', this._dll);
        },
        onLeave: function(retval) {
            var DLL = "Assembly-CSharp.dll";
            if (this._dll.indexOf(DLL) != -1) {
                console.log(JSON.stringify({
                    retval: retval,
                    name: this._dll,
                    symbols: Module.enumerateSymbolsSync(DLL),
                    exports: Module.enumerateExportsSync(DLL),
                    imports: Module.enumerateImportsSync(DLL),
                    // initialized: Module.ensureInitialized(DLL),
                    // moduleAddr: Process.getModuleByAddress(retval)
                }, null, 2));

            }
        }
    });
}
Java.perform(function() {
    try {
        awaitForCondition(hook);
    } catch (e) {
        console.error(e);
    }
});
```

#### Android make Toast
```javascript
Java.scheduleOnMainThread(function() {
	Java.use("android.widget.Toast")
	    .makeText(
            	Java.use("android.app.ActivityThread").currentApplication().getApplicationContext(),
            	"Text to Toast here",
            	0 // https://developer.android.com/reference/android/widget/Toast#LENGTH_LONG
        	)
        .show();
});
```

#### Hook java io InputStream
```javascript
function binaryToHexToAscii(array, readLimit) {
    var result = [];
    // read 100 bytes #performance
    readLimit = readLimit || 100;
    for (var i = 0; i < readLimit; ++i) {
        result.push(String.fromCharCode( // hex2ascii part
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
                16
            )
        ));
    }
    return result.join('');
}

function hookInputStream() {
    Java.use('java.io.InputStream')['read'].overload('[B').implementation = function(b) {
        // execute original and save return value
        var retval = this.read(b);
        var resp = binaryToHexToAscii(b);
        // conditions to not print garbage packets
        var reExcludeList = new RegExp(['Mmm'/*, 'Ping' /*, ' Yo'*/].join('|'));
        if ( ! reExcludeList.test(resp) ) {
            console.log(resp);
        }
        var reIncludeList = new RegExp(['AAA', 'BBB', 'CCC'].join('|')); 
        if ( reIncludeList.test(resp) ) {
            send( binaryToHexToAscii(b, 1200) );
        }
        return retval;
    };
}

// Main
Java.perform(hookInputStream);
```










#### TODOs 
- Add GIFs & docs
- Add links to /scripts
- Extend universal SSL unpinning for [ios](https://codeshare.frida.re/@dki/ios10-ssl-bypass/) [andoid 1](https://github.com/Fuzion24/JustTrustMe/blob/master/app/src/main/java/just/trust/me/Main.java) [android 2](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)

- References overview:
* https://github.com/mwrlabs/needle/blob/master/needle/modules/hooking/frida/script_touch-id-bypass.py
* https://github.com/as0ler/frida-scripts/blob/master/NSFileManager_Hooker.py
* https://techblog.mediaservice.net/2017/09/tracing-arbitrary-methods-and-function-calls-on-android-and-ios/
* https://zhiwei.li/text/2016/02/01/%E7%BC%96%E8%AF%91frida/
* https://kov4l3nko.github.io/blog/2018-05-27-sll-pinning-hook-sectrustevaluate/
* https://www.codemetrix.net/hacking-android-apps-with-frida-1/
* https://awakened1712.github.io/hacking/hacking-frida/
