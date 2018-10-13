## Table of Contents

### Native

<details>
<summary>View contents</summary>

* [`Intercept open`](#intercept-open)
* [`Execute shell command`](#execute-shell-command)
* [`List modules`][#list-modules)
* [`Log SQLite query`](#log-sqlite-query)

</details>

### Android

<details>
<summary>View contents</summary>

* [`Enumerate loaded classes`](#enumerate-loaded-classes) 
* [`Class description`](#class-description)
* [`Turn WiFi off`](#turn-wifi-off)
* [`Get IMEI`](#get-imei)
* [`Hook io InputStream`](#hook-io-inputstream)
* [`Android make Toast`](#android-make-toast)
* [`Await for specific module to load`](#await-for-condition)
* [`Webview URLS`](#webview-urls)
* [`Print all runtime strings & stacktrace`](#print-runtime-strings)
* [`Hook JNI by address`](#hook-jni-by-address)
* [`Hook constructor`](#hook-constructor)
* [`Hook Java refelaction`](#hook-refelaction)

</details>

### iOS

<details>
<summary>View contents</summary>

* [`iOS alert box`](#ios-alert-box) 
* [`File access`](#file-access)
* [`Observe class`](#observe-class)
* [`Find application UUID`](#find-application-uuid)
* [`Extract cookies`](#extract-cookies)
* [`Describe class members`](#describe-class-members)
* [`Class hierarchy`](#class-hierarchy) 

</details>

#### Intercept Open

An example for intercepting `libc#open` & logging backtrace if specific file was opened.

```js
Interceptor.attach(Module.findExportByName("/system/lib/libc.so", "open"), {
	onEnter: function(args) {
		// debug only the intended calls
		this.flag = false;
		var filename = Memory.readCString(ptr(args[0]));
		if (filename.indexOf("something") != -1) {
			this.flag = true;
			var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
			console.log("file name [ " + Memory.readCString(ptr(args[0])) + " ]\nBacktrace:" + backtrace);
		}
	},
	onLeave: function(retval) {
		if (this.flag) // passed from onEnter
			console.warn("\nretval: " + retval);
	}
});
```

<details>
<summary>Output example</summary>

TODO

</details>

<br>[⬆ Back to top](#table-of-contents)

#### Execute shell command


```python
import frida
from frida_tools.application import Reactor
import threading
import click


class Shell(object):
    def __init__(self, argv, env):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._stop_requested.wait())

        self._device = frida.get_usb_device()
        self._sessions = set()

        self._device.on("child-added", lambda child: self._reactor.schedule(lambda: self._on_child_added(child)))
        self._device.on("child-removed", lambda child: self._reactor.schedule(lambda: self._on_child_removed(child)))
        self._device.on("output", lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data)))

        self.argv = argv
        self.env = env
        self.output = []  # stdout will pushed into array

    def exec(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        click.secho("✔ spawn(argv={})".format(self.argv), fg='green', dim=True)
        pid = self._device.spawn(self.argv, env=self.env, stdio='pipe')
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid):
        click.secho("✔ attach(pid={})".format(pid), fg='green', dim=True)
        session = self._device.attach(pid)
        session.on("detached", lambda reason: self._reactor.schedule(lambda: self._on_detached(pid, session, reason)))
        click.secho("✔ enable_child_gating()", fg='green', dim=True)
        session.enable_child_gating()
        # print("✔ resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)

    def _on_child_added(self, child):
        click.secho("⚡ child_added: {}".format(child), fg='green', dim=True)
        self._instrument(child.pid)

    @staticmethod
    def _on_child_removed(child):
        click.secho("⚡ child_removed: {}".format(child), fg='green', dim=True)

    def _on_output(self, pid, fd, data):
        # print("⚡ output: pid={}, fd={}, data={}".format(pid, fd, repr(data)))
        # fd=0 (input) fd=1(stdout) fd=2(stderr)
        if fd != 2:
            self.output.append(data)

    def _on_detached(self, pid, session, reason):
        click.secho("⚡ detached: pid={}, reason='{}'".format(pid, reason), fg='green', dim=True)
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    @staticmethod
    def _on_message(pid, message):
        click.secho("⚡ message: pid={}, payload={}".format(pid, message), fg='green', dim=True)
```

<details>
<summary>Usage example</summary>

List directory contents:

```python
def ls(folder):
    cmd = Shell(['/bin/sh', '-c', 'ls -la ' + folder], None)
    cmd.exec()
    for chunk in cmd.output:
        print(chunk.strip().decode())
```

</details>

<br>[⬆ Back to top](#table-of-contents)


#### List modules

```js
Process.enumerateModulesSync()
    .filter(function(m){ return m['path'].toLowerCase().indexOf('app') !=-1 ; })
    .forEach(function(m) {
        console.log(JSON.stringify(m, null, '  '));
        // to list exports use Module.enumerateExportsSync(m.name)
    });
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Log SQLite query
```js
Interceptor.attach(Module.findExportByName('libsqlite.so', 'sqlite3_prepare16_v2'), {
      onEnter: function(args) {
          console.log('DB: ' + Memory.readUtf16String(args[0]) + '\tSQL: ' + Memory.readUtf16String(args[1]));
      }
});
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Enumerate loaded classes

And save to a file named `pkg.classes`

```bash
$ frida -U com.pkg -qe 'Java.perform(function(){Java.enumerateLoadedClasses({"onMatch":function(c){console.log(c);}});});' -o pkg.classes
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)



#### Class description

Get class methods & members.

```js
Object.getOwnPropertyNames(Java.use('com.company.CustomClass').__proto__).join('\n\t')
```

If there is a name collision, method & member has the same name, an underscore will be added to member. [source](https://github.com/frida/frida-java/pull/21)
```js
	let fieldJsName = env.stringFromJni(fieldName);
	while (jsMethods.hasOwnProperty(fieldJsName)) {
		fieldJsName = '_' + fieldJsName;
	}
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Turn Wifi OFF

It will turn WiFi off on the creation of the first Acivity.

```js
var WifiManager = Java.use("android.net.wifi.WifiManager");
Java.use("android.app.Activity").onCreate.overload('android.os.Bundle').implementation = function() {
    var wManager = Java.cast(this.getSystemService("wifi"), WifiManager);
    console.log('isWifiEnabled', wManager.isWifiEnabled());
    wManager.setWifiEnabled(false);
    return this.$init();
}
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Get IMEI

Can also hook & change IMEI.

```js
function getIMEI(){
    console.log('IMEI =', Java.use("android.telephony.TelephonyManager").$new().getDeviceId());
}
Java.perform(getIMEI)
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Hook io InputStream

Hook `InputputStream` & print buffer as `ascii` with char limit & exclude list.

```js
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

Java.perform(hookInputStream);
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)


#### Android make Toast

```js
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

<details>
<summary>Output example</summary>
TODO
</details>
<br>[⬆ Back to top](#table-of-contents)

#### Await for condition
Await until specific DLL will load in Unity app, can implement hot swap.
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
            if (this._dll.endsWith("Assembly-CSharp.dll")) {
                console.log(JSON.stringify({
                    retval: retval,
                    name: this._dll
                }, null, 2));
            }
        }
    });
}
Java.perform(awaitForCondition(hook));
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)


#### Webview URLS

Log whenever WebView switch URL.

```js
Java.use("android.webkit.WebView").loadUrl.overload("java.lang.String").implementation = function (s) {
    send(s.toString());
    this.loadUrl.overload("java.lang.String").call(this, s);
};
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Print runtime strings 

Hoooking `toString` of StringBuilder/Buffer & printing stacktrace.

```js
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

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Hook JNI by address

Hook native method by module name and method address and print arguments.

```js
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

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Hook constructor
```js
Java.use('java.lang.StringBuilder').$init.overload('java.lang.String').implementation = function(stringArgument) {
      console.log("c'tor");
      return this.$init(stringArgument);
};
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Hook refelaction

`java.lang.reflect.Method#invoke(Object obj, Object... args, boolean bool)`

```javascript
  Java.use('java.lang.reflect.Method').invoke.overload('java.lang.Object', '[Ljava.lang.Object;', 'boolean').implementation = function(a,b,c) {
      console.log('hooked!', a, b, c);
      return this.invoke(a,b,c);
  };
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### iOS alert box

```js
var UIAlertController = ObjC.classes.UIAlertController;
var UIAlertAction = ObjC.classes.UIAlertAction;
var UIApplication = ObjC.classes.UIApplication;
var handler = new ObjC.Block({ retType: 'void', argTypes: ['object'], implementation: function () {} });

ObjC.schedule(ObjC.mainQueue, function () {
  var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_('Frida', 'Hello from Frida', 1);
  var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
  alert.addAction_(defaultAction);
  // Instead of using `ObjC.choose()` and looking for UIViewController instances on the heap, we have direct access through UIApplication:
  UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
})
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)


#### File Access

Log each file open

```js
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        console.log('open' , ObjC.Object(args[2]).toString());
    }
});
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Observe class
```js
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

<details>
<summary>Output example</summary>
	
`observeClass('Someclass$innerClass');`

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

</details>

<br>[⬆ Back to top](#table-of-contents)


#### Find iOS application UUID 

Get UUID for specific path when attached to an app by reading plist file under each app container.

```js
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

<details>
<summary>Output example</summary>
TODO	
</details>

<br>[⬆ Back to top](#table-of-contents)


#### Extract cookies

```js
 var cookieJar = [];
 var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
 for (var i = 0, l = cookies.count(); i < l; i++) {
     var cookie = cookies['- objectAtIndex:'](i);
     cookieJar.push(cookie.Name() + '=' + cookie.Value());
 }
 console.log(cookieJar.join("; "));
```

<details>
<summary>Output example</summary>
TODO	
</details>

<br>[⬆ Back to top](#table-of-contents)


#### Describe class members

Print map of members (with values) for each class instance

```js
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

<details>
<summary>Output example</summary>
TODO	
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Class hierarchy

Object.keys(ObjC.classes) will list all available Objective C classes,
but actually this will return all classes loaded in current process, including system frameworks.
If we want something like weak_classdump, to list classes from executable it self only, Objective C runtime already provides such function [objc_copyClassNamesForImage](#https://developer.apple.com/documentation/objectivec/1418485-objc_copyclassnamesforimage?language=objc)

```js
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


<details>
<summary>Output example</summary>
TODO	
</details>

<br>[⬆ Back to top](#table-of-contents)



#### TODOs 
- Add GIFs & examples
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
