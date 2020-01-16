![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square) & also output examples

## Table of Contents

<details>
<summary>Native</summary>

* [`One time watchpoint`](#one-time-watchpoint)
* [`Socket activity`](#socket-activity)
* [`Intercept open`](#intercept-open)
* [`Execute shell command`](#execute-shell-command)
* [`List modules`](#list-modules)
* [`Log SQLite query`](#log-sqlite-query)
* [`Log method arguments`](#log-method-arguments)
* [`Intercept entire module`](#intercept-entire-module)
* [`Dump memory segments`](#dump-memory-segments)
* [`Memory scan`](#memory-scan)
* [`Stalker`](#stalker)

</details>

<details>
<summary>Android</summary>

* [`Get system property`](#system-property-get)
* [`Reveal manually registered native symbols`](#reveal-native-methods)
* [`Enumerate loaded classes`](#enumerate-loaded-classes) 
* [`Class description`](#class-description)
* [`Turn WiFi off`](#turn-wifi-off)
* [`Set proxy`](#set-proxy)
* [`Get IMEI`](#get-imei)
* [`Hook io InputStream`](#hook-io-inputstream)
* [`Android make Toast`](#android-make-toast)
* [`Await for specific module to load`](#await-for-condition)
* [`Webview URLS`](#webview-urls)
* [`Print all runtime strings & stacktrace`](#print-runtime-strings)
* [`String comparison`](#string-comparison)
* [`Hook JNI by address`](#hook-jni-by-address)
* [`Hook constructor`](#hook-constructor)
* [`Hook Java reflection`](#hook-refelaction)
* [`Trace class`](#trace-class)
* [`Hooking Unity3d`](https://github.com/iddoeldor/mplus)
* [`Get Android ID`](#get-android-id)
* [`Change location`](#change-location)
* [`Bypass FLAG_SECURE`](#bypass-flag_secure)
* [`Shared Preferences update`](#shared-preferences-update)
* [`Hook all method overloads`](#hook-overloads)
* [`Register broadcast receiver`](#register-broadcast-receiver)
* File system access hook `$ frida --codeshare FrenchYeti/android-file-system-access-hook -f com.example.app --no-pause`
</details>

<details>
<summary>iOS</summary>

* [`OS Log`](#os-log)
* [`iOS alert box`](#ios-alert-box) 
* [`File access`](#file-access)
* [`Observe class`](#observe-class)
* [`Find application UUID`](#find-ios-application-uuid)
* [`Extract cookies`](#extract-cookies)
* [`Describe class members`](#describe-class-members)
* [`Class hierarchy`](#class-hierarchy) 
* [`Hook refelaction`](#hook-refelaction)
* [`Device properties`](#device-properties)
* [`Take screenshot`](#take-screenshot)

</details>

<details>
<summary>Windows</summary>	

![HAHAHA. No.](https://i.kym-cdn.com/photos/images/original/000/551/854/06f.jpg)

</details>
<details>
	<summary>Sublime snippets</summary>
	
	{
	    "scope": "source.js",
	    "completions": [
		{"trigger": "fridainterceptor", "contents": "Interceptor.attach(\n    ptr,\n    {\n        onEnter:function(args) {\n\n        },\n        onLeave: function(retval) {\n\n        }\n    }\n)"},
		{"trigger": "fridaperform", "contents": "function main(){\n    console.log('main()');\n}\n\nconsole.log('script loaded');\nJava.perform(main);"},
		{"trigger": "fridause", "contents": "var kls = Java.use('kls');"},
		{"trigger": "fridahex", "contents": "hexdump(\n    ptr,\n    {\n         offset: 0,\n         length: ptr_size\n     }\n);" },
		{"trigger": "fridabacktrace", "contents": "console.log('called from:\\n' +\n        Thread.backtrace(this.context, Backtracer.ACCURATE)\n        .map(DebugSymbol.fromAddress).join('\\n') + '\\n'\n);"},
		{"trigger": "fridamods", "contents": "var mods = Process.enumerateModules().filter(function(mod){\n    return mod.name.includes(\"<name>\");\n});"},
		{"trigger": "fridaexport", "contents": "Module.findExportByName(null, \"<export_name>\");"},
		{"trigger": "fridabase", "contents": "Module.findBaseAddress(name);"},
		{"trigger": "fridaoverload", "contents": "kls.method_name.overload().implementation=function(){}"}
	    ]
	}
</details>


<details>
<summary>Vim snippets</summary>	

To list abbreviations `:ab`

Expand by writing `key` and `<Space>`

* Add to `~/.vimrc`

```
ab fridaintercept Interceptor.attach(ptr, {<CR><Tab>onEnter: function(args) {<CR><CR>},<CR>onLeave: function(retval) {<CR><CR>}<CR><BS>})
ab fridabacktrace console.warn(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));<ESC>F(3;
ab fridadescribe console.log(Object.getOwnPropertyNames(Java.use('$').__proto__).join('\n\t'))<Esc>F$
```

</details>

<hr />


#### One time watchpoint

Intercept `funcPtr` & log who read/write to `x2` via removing permissions w/ `mprotect`.

```js
Process.setExceptionHandler(function(exp) {
  console.warn(JSON.stringify(Object.assign(exp, { _lr: DebugSymbol.fromAddress(exp.context.lr), _pc: DebugSymbol.fromAddress(exp.context.pc) }), null, 2));
  Memory.protect(exp.memory.address, Process.pointerSize, 'rw-');
  // can also use `new NativeFunction(Module.findExportByName(null, 'mprotect'), 'int', ['pointer', 'uint', 'int'])(parseInt(this.context.x2), 2, 0)`
  return true; // goto PC 
});

Interceptor.attach(funcPtr, {
  onEnter: function (args) {
    console.log('onEnter', JSON.stringify({
      x2: this.context.x2,
      mprotect_ret: Memory.protect(this.context.x2, 2, '---'),
      errno: this.errno
    }, null, 2));
  },
  onLeave: function (retval) {
    console.log('onLeave');
  }
});
```

<details>
<summary>Output example</summary>

```
[iOS Device::com.app]-> onEnter {
  "x2": "0x1c145c6e0",
  "mprotect_ret": true,
  "errno": 2
}
{
  "type": "access-violation",
  "address": "0x1853b0198",
  "memory": {
    "operation": "read",
    "address": "0x1c145c6e0"
  },
  "context": {
    "lr": "0x100453358",
    "fp": "0x16fb2e860",
    "x28": "0x0",
    "x27": "0x0",
    "x26": "0x104312600",
    "x25": "0x0",
    "x24": "0x0",
    "x23": "0x0",
    "x22": "0x0",
    "x21": "0xb000000422bbda03",
    "x20": "0x1c4a22560",
    "x19": "0xb000000422bbda03",
    "x18": "0x0",
    "x17": "0x100d25290",
    "x16": "0x1853b0190",
    "x15": "0x0",
    "x14": "0x5",
    "x13": "0xe5a1c4119597",
    "x12": "0x10e80ca30",
    "x11": "0x180000003f",
    "x10": "0x10e80ca00",
    "x9": "0x1020ad7c3",
    "x8": "0x0",
    "x7": "0x0",
    "x6": "0x0",
    "x5": "0x0",
    "x4": "0xb000000422bbda03",
    "x3": "0x1c4a22560",
    "x2": "0x1c145c6e0",
    "x1": "0x1020ad7c3",
    "x0": "0x1c145c6e0",
    "sp": "0x16fb2e790",
    "pc": "0x1853b0198"
  },
  "nativeContext": "0x16fc42b24"
}
onLeave
```


</details>

<br>[⬆ Back to top](#table-of-contents)



#### Socket activity

```js
Process
  .getModuleByName({ linux: 'libc.so', darwin: 'libSystem.B.dylib', windows: 'ws2_32.dll' }[Process.platform])
  .enumerateExports().filter(ex => ex.type === 'function' && ['connect', 'recv', 'send', 'read', 'write'].some(prefix => ex.name.indexOf(prefix) === 0))
  .forEach(ex => {
    Interceptor.attach(ex.address, {
      onEnter: function (args) {
        var fd = args[0].toInt32();
        if (Socket.type(fd) !== 'tcp')
          return;
        var address = Socket.peerAddress(fd);
        if (address === null)
          return;
        console.log(fd, ex.name, address.ip + ':' + address.port);
      }
    })
  })
```

<details>
<summary>Output example</summary>
	
Android example
```sh
# wrap the script above inside Java.perform
$ frida -Uf com.example.app -l script.js --no-pause
[Android Model-X::com.example.app]-> 117 write 5.0.2.1:5242
117 read 5.0.2.1:5242
135 write 5.0.2.1:4244
135 read 5.0.2.1:4244
135 read 5.0.2.1:4244
```

</details>

<br>[⬆ Back to top](#table-of-contents)

#### Intercept Open

An example for intercepting `libc#open` & logging backtrace if specific file was opened.

```js
Interceptor.attach(Module.findExportByName("/system/lib/libc.so", "open"), {
  onEnter: function(args) {
    this.flag = false;
    var filename = Memory.readCString(ptr(args[0]));
    console.log('filename =', filename)
    if (filename.endsWith(".xml")) {
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


```js
var fds = {}; // for f in /proc/`pidof $APP`/fd/*; do echo $f': 'readlink $f; done
Interceptor.attach(Module.findExportByName(null, 'open'), {
  onEnter: function (args) {
    var fname = args[0].readCString();
    if (fname.endsWith('.jar')) {
      this.flag = true;
      this.fname = fname;
    }
  },
  onLeave: function (retval) {
    if (this.flag) {
      fds[retval] = this.fname;
    }
  }
});
['read', 'pread', 'readv'].forEach(fnc => {
  Interceptor.attach(Module.findExportByName(null, fnc), {
    onEnter: function (args) {
      var fd = args[0];
      if (fd in fds)
        console.log(`${fnc}: ${fds[fd]}
	\t${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}`);
    }
  });
});
```

<details>
<summary>Output example</summary>
Intecepting `com.android.chrome`
	
![](https://github.com/iddoeldor/frida-snippets/blob/master/gif/intercept_open_chrome_android.gif)


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

Pull binary from iOS

```python
cmd = Shell(['/bin/sh', '-c', 'cat /System/Library/PrivateFrameworks/Example.framework/example'], None)
cmd.exec()
with open('/tmp/example', 'wb+') as f:
    f.writelines(cmd.output)
 # $ file /tmp/example
 # /tmp/example: Mach-O 64-bit 64-bit architecture=12 executable
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

List modules & exports

```js
sudo frida Process --no-pause --eval 'var x={};Process.enumerateModulesSync().forEach(function(m){x[m.name] = Module.enumerateExportsSync(m.name)});x' -q | less +F
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

#### system property get

```js
Interceptor.attach(Module.findExportByName(null, '__system_property_get'), {
	onEnter: function (args) {
		this._name = args[0].readCString();
		this._value = args[1];
	},
	onLeave: function (retval) {
		console.log(JSON.stringify({
			result_length: retval,
			name: this._name,
			val: this._value.readCString()
		}));
	}
});
```

<details>
<summary>Output example</summary>

```sh
{"result_length":"0x0","name":"ro.kernel.android.tracing","val":""}
{"result_length":"0x0","name":"ro.config.hw_log","val":""}
{"result_length":"0x0","name":"ro.config.hw_module_log","val":""}
{"result_length":"0x1","name":"ro.debuggable","val":"0"}
{"result_length":"0x1","name":"persist.sys.huawei.debug.on","val":"0"}
{"result_length":"0x1","name":"ro.logsystem.usertype","val":"6"}
{"result_length":"0x6","name":"ro.board.platform","val":"hi6250"}
{"result_length":"0x4","name":"persist.sys.enable_iaware","val":"true"}
{"result_length":"0x1","name":"persist.sys.cpuset.enable","val":"1"}
{"result_length":"0x4","name":"persist.sys.cpuset.subswitch","val":"1272"}
{"result_length":"0x4","name":"persist.sys.boost.durationms","val":"1000"}
{"result_length":"0x4","name":"persist.sys.boost.isbigcore","val":"true"}
{"result_length":"0x7","name":"persist.sys.boost.freqmin.b","val":"1805000"}
{"result_length":"0x4","name":"persist.sys.boost.ipapower","val":"3500"}
{"result_length":"0x0","name":"persist.sys.boost.skipframe","val":""}
{"result_length":"0x0","name":"persist.sys.boost.byeachfling","val":""}
{"result_length":"0x1","name":"debug.force_rtl","val":"0"}
{"result_length":"0x0","name":"ro.hardware.gralloc","val":""}
{"result_length":"0x6","name":"ro.hardware","val":"hi6250"}
{"result_length":"0x0","name":"ro.kernel.qemu","val":""}
{"result_length":"0x0","name":"ro.config.hw_force_rotation","val":""}
{"result_length":"0x0","name":"persist.fb_auto_alloc","val":""}
{"result_length":"0x0","name":"ro.config.hw_lock_res_whitelist","val":""}
{"result_length":"0x3","name":"ro.sf.lcd_density","val":"480"}
{"result_length":"0x0","name":"persist.sys.dpi","val":""}
{"result_length":"0x0","name":"persist.sys.rog.width","val":""}
{"result_length":"0x4","name":"dalvik.vm.usejitprofiles","val":"true"}
{"result_length":"0x1","name":"debug.atrace.tags.enableflags","val":"0"}
{"result_length":"0x1","name":"ro.debuggable","val":"0"}
{"result_length":"0x1","name":"debug.force_rtl","val":"0"}
{"result_length":"0x0","name":"ro.config.hw_lock_res_whitelist","val":""}
....
```
	
</details>

<br>[⬆ Back to top](#table-of-contents)



#### Reveal native methods

`registerNativeMethods` can be used as anti reversing technique to the native .so libraries, e.g. hiding the symbols as much as possible, obfuscating the exported symbols and eventually adding some protection over the JNI bridge.
[source](https://stackoverflow.com/questions/51811348/find-manually-registered-obfuscated-native-function-address)

```js
var RevealNativeMethods = function() {
  var pSize = Process.pointerSize;
  var env = Java.vm.getEnv();
  var RegisterNatives = 215, FindClassIndex = 6; // search "215" @ https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html
  var jclassAddress2NameMap = {};
  function getNativeAddress(idx) {
    return env.handle.readPointer().add(idx * pSize).readPointer();
  }
  // intercepting FindClass to populate Map<address, jclass>
  Interceptor.attach(getNativeAddress(FindClassIndex), {
    onEnter: function(args) {
      jclassAddress2NameMap[args[0]] = args[1].readCString();
    }
  });
  // RegisterNative(jClass*, .., JNINativeMethod *methods[nMethods], uint nMethods) // https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#977
  Interceptor.attach(getNativeAddress(RegisterNatives), {
    onEnter: function(args) {
      for (var i = 0, nMethods = parseInt(args[3]); i < nMethods; i++) {
        /*
          https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#129
          typedef struct {
             const char* name;
             const char* signature;
             void* fnPtr;
          } JNINativeMethod;
        */
        var structSize = pSize * 3; // = sizeof(JNINativeMethod)
        var methodsPtr = ptr(args[2]);
        var signature = methodsPtr.add(i * structSize + pSize).readPointer();
        var fnPtr = methodsPtr.add(i * structSize + (pSize * 2)).readPointer(); // void* fnPtr
        var jClass = jclassAddress2NameMap[args[0]].split('/');
        console.log('\x1b[3' + '6;01' + 'm', JSON.stringify({
          module: DebugSymbol.fromAddress(fnPtr)['moduleName'], // https://www.frida.re/docs/javascript-api/#debugsymbol
          package: jClass.slice(0, -1).join('.'),
          class: jClass[jClass.length - 1],
          method: methodsPtr.readPointer().readCString(), // char* name
          signature: signature.readCString(), // char* signature TODO Java bytecode signature parser { Z: 'boolean', B: 'byte', C: 'char', S: 'short', I: 'int', J: 'long', F: 'float', D: 'double', L: 'fully-qualified-class;', '[': 'array' } https://github.com/skylot/jadx/blob/master/jadx-core/src/main/java/jadx/core/dex/nodes/parser/SignatureParser.java
          address: fnPtr
        }), '\x1b[39;49;00m');
      }
    }
  });
}

Java.perform(RevealNativeMethods);
```

@OldVersion
```js
var fIntercepted = false;

function revealNativeMethods() {
    if (fIntercepted === true) {
        return;
    }
    var jclassAddress2NameMap = {};
    var androidRunTimeSharedLibrary = "libart.so"; // may change between devices
    Module.enumerateSymbolsSync(androidRunTimeSharedLibrary).forEach(function(symbol){
        switch (symbol.name) {
            case "_ZN3art3JNI21RegisterNativeMethodsEP7_JNIEnvP7_jclassPK15JNINativeMethodib":
                /*
                    $ c++filt "_ZN3art3JNI21RegisterNativeMethodsEP7_JNIEnvP7_jclassPK15JNINativeMethodib"
                    art::JNI::RegisterNativeMethods(_JNIEnv*, _jclass*, JNINativeMethod const*, int, bool)
                */
                var RegisterNativeMethodsPtr = symbol.address;
                console.log("RegisterNativeMethods is at " + RegisterNativeMethodsPtr);
                Interceptor.attach(RegisterNativeMethodsPtr, {
                    onEnter: function(args) {
                        var methodsPtr = ptr(args[2]);
                        var methodCount = parseInt(args[3]);
                        for (var i = 0; i < methodCount; i++) {
                            var pSize = Process.pointerSize;
                            /*
                                https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#129
                                typedef struct {
                                    const char* name;
                                    const char* signature;
                                    void* fnPtr;
                                } JNINativeMethod;
                            */
                            var structSize = pSize * 3; // JNINativeMethod contains 3 pointers
                            var namePtr = Memory.readPointer(methodsPtr.add(i * structSize));
                            var sigPtr = Memory.readPointer(methodsPtr.add(i * structSize + pSize));
                            var fnPtrPtr = Memory.readPointer(methodsPtr.add(i * structSize + (pSize * 2)));
                            // output schema: className#methodName(arguments)returnVal@address
                            console.log(
                                // package & class, replacing forward slash with dot for convenience
                                jclassAddress2NameMap[args[0]].replace(/\//g, '.') +
                                '#' + Memory.readCString(namePtr) + // method
                                Memory.readCString(sigPtr) + // signature (arguments & return type)
                                '@' + fnPtrPtr // C side address
                            );
                        }
                    },
                    onLeave: function (ignoredReturnValue) {}
                });
                break;
            case "_ZN3art3JNI9FindClassEP7_JNIEnvPKc": // art::JNI::FindClass
                Interceptor.attach(symbol.address, {
                    onEnter: function(args) {
                        if (args[1] != null) {
                            jclassAddress2NameMap[args[0]] = Memory.readCString(args[1]);
                        }
                    },
                    onLeave: function (ignoredReturnValue) {}
                });
                break;
        }
    });
    fIntercepted = true;
}

Java.perform(revealNativeMethods);
```

<details>
<summary>Output example</summary>

```sh
$ frida -Uf com.google.android.apps.photos --no-pause -l script.js
```

```sh
{"class":"org/chromium/net/GURLUtils","method":"nativeGetOrigin","signature":"(Ljava/lang/String;)Ljava/lang/String;","address":"0x..da910"}
..
```

</details>

<br>[⬆ Back to top](#table-of-contents)

#### Log method arguments


```python
def on_message(m, _data):
    if m['type'] == 'send':
        print(m['payload'])
    elif m['type'] == 'error':
        print(m)


def switch(argument_key, idx):
    """
    c/c++ variable type to javascript reader switch implementation
    # TODO handle other arguments, [long, longlong..]
    :param argument_key: variable type
    :param idx: index in symbols array
    :return: javascript to read the type of variable
    """
    argument_key = argument_key.replace(' ', '')
    return '%d: %s' % (idx, {
        'int': 'args[%d].toInt32(),',
        'unsignedint': 'args[%d].toInt32(),',
        'std::string': 'Memory.readUtf8String(Memory.readPointer(args[%d])),',
        'bool': 'Boolean(args[%d]),'
    }[argument_key] % idx)


def list_symbols_from_object_files(module_id):
    import subprocess
    return subprocess.getoutput('nm --demangle --dynamic %s' % module_id)


def parse_nm_output(nm_stdout, symbols):
    for line in nm_stdout.splitlines():
        split = line.split()
        open_parenthesis_idx = line.find('(')
        raw_arguments = [] if open_parenthesis_idx == -1 else line[open_parenthesis_idx + 1:-1]
        if len(raw_arguments) > 0:  # ignore methods without arguments
            raw_argument_list = raw_arguments.split(',')
            symbols.append({
                'address': split[0],
                'type': split[1],  # @see Symbol Type Table
                'name': split[2][:split[2].find('(')],  # method name
                'args': raw_argument_list
            })


def get_js_script(method, module_id):
    js_script = """
        var moduleName = "{{moduleName}}", nativeFuncAddr = {{methodAddress}};
        Interceptor.attach(Module.findExportByName(null, "dlopen"), {
            onEnter: function(args) {
                this.lib = Memory.readUtf8String(args[0]);
                console.log("[*] dlopen called with: " + this.lib);
            },
            onLeave: function(retval) {
                if (this.lib.endsWith(moduleName)) {
                    Interceptor.attach(Module.findBaseAddress(moduleName).add(nativeFuncAddr), {
                        onEnter: function(args) {
                            console.log("[*] hook invoked", JSON.stringify({{arguments}}, null, '\t'));
                        }
                    });
                }
            }
        });
    """
    replace_map = {
        '{{moduleName}}': module_id,
        '{{methodAddress}}': '0x' + method['address'],
        '{{arguments}}': '{' + ''.join([switch(method['args'][i], i + 1) for i in range(len(method['args']))]) + '}'
    }
    for k, v in replace_map.items():
        js_script = js_script.replace(k, v)
    print('[+] JS Script:\n', js_script)
    return js_script


def main(app_id, module_id, method):
    """
    $ python3.x+ script.py --method SomeClass::someMethod --app com.company.app --module libfoo.so
    :param app_id: application identifier / bundle id 
    :param module_id: shared object identifier / known suffix, will iterate loaded modules (@see dlopen) 
    :param method: method/symbol name
    :return: hook native method and print arguments when invoked
    """
    # TODO extract all app's modules via `adb shell -c 'ls -lR /data/app/' + app_if + '*' | grep "\.so"`

    nm_stdout = list_symbols_from_object_files(module_id)

    symbols = []
    parse_nm_output(nm_stdout, symbols)

    selection_idx = None
    for idx, symbol in enumerate(symbols):
        if method is None:  # if --method flag is not passed
            print("%4d) %s (%d)" % (idx, symbol['name'], len(symbol['args'])))
        elif method == symbol['name']:
            selection_idx = idx
            break
    if selection_idx is None:
        if method is None:
            selection_idx = input("Enter symbol number: ")
        else:
            print('[+] Method not found, remove method flag to get list of methods to select from, `nm` stdout:')
            print(nm_stdout)
            exit(2)

    method = symbols[int(selection_idx)]
    print('[+] Selected method: %s' % method['name'])
    print('[+] Method arguments: %s' % method['args'])

    from frida import get_usb_device
    device = get_usb_device()
    pid = device.spawn([app_id])
    session = device.attach(pid)
    script = session.create_script(get_js_script(method, module_id))
    script.on('message', on_message)
    script.load()
    device.resume(app_id)
    # keep hook alive
    from sys import stdin
    stdin.read()


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('--app', help='app identifier "com.company.app"')
    parser.add_argument('--module', help='loaded module name "libfoo.2.so"')
    parser.add_argument('--method', help='method name "SomeClass::someMethod", if empty it will print select-list')
    args = parser.parse_args()
    main(args.app, args.module, args.method)

```

<details>
<summary>Symbol Type Table</summary>
<pre>
    "A" The symbol's value is absolute, and will not be changed by further linking.
    "B" The symbol is in the uninitialized data section (known as BSS).
    "C" The symbol is common.  Common symbols are uninitialized data.
       When linking, multiple common symbols may appear	with the same name.  
       If the symbol is defined anywhere, the common symbols are treated as undefined	references.
    "D" The symbol is in the initialized data section.
    "G" The symbol is in an initialized data section for small objects.
       Some object file formats permit more efficient access to small data objects, such as a global int variable as 
       opposed to a large global array.
    "I" The symbol is an indirect reference to another symbol.
       This is a GNU extension to the a.out object file format which is rarely used.
    "N" The symbol is a debugging symbol.
    "R" The symbol is in a read only data section.
    "S" The symbol is in an uninitialized data section for small objects.
    "T" The symbol is in the text (code) section.
    "U" The symbol is undefined.
    "V" The symbol is a weak object. When a weak defined symbol is linked with a normal defined symbol, 
        the normal defined symbol is used with no error.  
        When a weak undefined symbol is linked and the symbol is not defined, the value of the weak symbol becomes 
        zero with no error.
    "W" The symbol is a weak symbol that has not been specifically tagged as a weak object symbol. 
        When a weak defined symbol is linked with a normal defined symbol, 
        the normal defined symbol is used with no error.  
        When a weak undefined symbol is linked and the symbol is not defined, the value of the symbol is determined 
        in a system-specific manner without error.  
        On some systems, uppercase indicates that a default value has been specified.
    "-" The symbol is a stabs symbol in an a.out object file.  
        In this case, the next values printed are the stabs other field, the stabs desc field, and the stab type.  
        Stabs symbols are used to hold debugging information.
    "?" The symbol type is unknown, or object file format specific.
</pre>
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
Java.use("android.app.Activity").onCreate.overload("android.os.Bundle").implementation = function(bundle) {
    var wManager = Java.cast(this.getSystemService("wifi"), WifiManager);
    console.log('isWifiEnabled ?', wManager.isWifiEnabled());
    wManager.setWifiEnabled(false);
    this.$init(bundle);
}
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Set proxy

It will set a system-wide proxy using the supplied IP address and port.

```js
var ActivityThread      = Java.use('android.app.ActivityThread');
var ConnectivityManager = Java.use('android.net.ConnectivityManager');
var ProxyInfo           = Java.use('android.net.ProxyInfo');

var proxyInfo           = ProxyInfo.$new('192.168.1.10', 8080, ''); // change to null in order to disable the proxy.
var context = ActivityThread.currentApplication().getApplicationContext();
var connectivityManager = Java.cast(context.getSystemService('connectivity'), ConnectivityManager);
connectivityManager.setGlobalProxy(proxyInfo);
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
      if (ret.indexOf('') != -1) {
        // print stacktrace if return value contains specific string
        Java.perform(function() {
          var jAndroidLog = Java.use("android.util.Log"), jException = Java.use("java.lang.Exception");
          console.log( jAndroidLog.getStackTraceString( jException.$new() ) );
        }); 
      }   
      send('[' + i + '] ' + ret);
      return ret;
    }   
  }); 
});
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### String comparison


```js
Java.perform(function() {
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

#### Hook reflection

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

#### Trace class

Tracing class method, with pretty colors and options to print as JSON & stacktrace.

TODO add trace for c'tor.

```js

var Color = {
    RESET: "\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", Green: "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01",
    Light: {
        Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", Green: "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11"
    }
};

/**
 *
 * @param input. 
 *      If an object is passed it will print as json 
 * @param kwargs  options map {
 *     -l level: string;   log/warn/error
 *     -i indent: boolean;     print JSON prettify
 *     -c color: @see ColorMap
 * }
 */
var LOG = function (input, kwargs) {
    kwargs = kwargs || {};
    var logLevel = kwargs['l'] || 'log', colorPrefix = '\x1b[3', colorSuffix = 'm';
    if (typeof input === 'object')
        input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
    if (kwargs['c'])
        input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
    console[logLevel](input);
};

var printBacktrace = function () {
    Java.perform(function() {
        var android_util_Log = Java.use('android.util.Log'), java_lang_Exception = Java.use('java.lang.Exception');
        // getting stacktrace by throwing an exception
        LOG(android_util_Log.getStackTraceString(java_lang_Exception.$new()), { c: Color.Gray });
    });
};

function traceClass(targetClass) {
    var hook;
    try {
        hook = Java.use(targetClass);
    } catch (e) {
        console.error("trace class failed", e);
        return;
    }

    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();

    var parsedMethods = [];
    methods.forEach(function (method) {
        var methodStr = method.toString();
        var methodReplace = methodStr.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
         parsedMethods.push(methodReplace);
    });

    uniqBy(parsedMethods, JSON.stringify).forEach(function (targetMethod) {
        traceMethod(targetClass + '.' + targetMethod);
    });
}

function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1)
        return;

    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    LOG({ tracing: targetClassMethod, overloaded: overloadCount }, { c: Color.Green });

    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            var log = { '#': targetClassMethod, args: [] };

            for (var j = 0; j < arguments.length; j++) {
                var arg = arguments[j];
                // quick&dirty fix for java.io.StringWriter char[].toString() impl because frida prints [object Object]
                if (j === 0 && arguments[j]) {
                    if (arguments[j].toString() === '[object Object]') {
                        var s = [];
                        for (var k = 0, l = arguments[j].length; k < l; k++) {
                            s.push(arguments[j][k]);
                        }
                        arg = s.join('');
                    }
                }
                log.args.push({ i: j, o: arg, s: arg ? arg.toString(): 'null'});
            }

            var retval;
            try {
                retval = this[targetMethod].apply(this, arguments); // might crash (Frida bug?)
                log.returns = { val: retval, str: retval ? retval.toString() : null };
            } catch (e) {
                console.error(e);
            }
            LOG(log, { c: Color.Blue });
            return retval;
        }
    }
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}


var Main = function() {
    Java.perform(function () { // avoid java.lang.ClassNotFoundException
        [
            // "java.io.File",
            'java.net.Socket'
        ].forEach(traceClass);

        Java.use('java.net.Socket').isConnected.overload().implementation = function () {
            LOG('Socket.isConnected.overload', { c: Color.Light.Cyan });
            printBacktrace();
            return true;
        }
    });
};

Java.perform(Main);


```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Get Android ID
The [ANDROID_ID](https://developer.android.com/reference/android/provider/Settings.Secure.html#ANDROID_ID) is unique in each application in Android.


```javascript
function getContext() {
  return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver();
}

function logAndroidId() {
  console.log('[-]', Java.use('android.provider.Settings$Secure').getString(getContext(), 'android_id'));
}
```

<details>
<summary>Output example</summary>
https://stackoverflow.com/a/54818023/2655092
</details>

<br>[⬆ Back to top](#table-of-contents)


#### Change location


```js
Java.perform(() => {
	var Location = Java.use('android.location.Location');
	Location.getLatitude.implementation = function() {
		return LATITUDE;
	}
	Location.getLongitude.implementation = function() {
		return LONGITUDE;
	}
})
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)



#### Bypass FLAG_SECURE
Bypass screenshot prevention [stackoverflow question](https://stackoverflow.com/questions/9822076/how-do-i-prevent-android-taking-a-screenshot-when-my-app-goes-to-the-background)

```javascript
Java.perform(function() {
    Java.use('android.view.SurfaceView').setSecure.overload('boolean').implementation = function(flag){
        console.log('[1] flag:', flag);
        this.call(false);
    };
    var LayoutParams = Java.use('android.view.WindowManager$LayoutParams');
    Java.use('android.view.ViewWindow').setFlags.overload('int', 'int').implementation = function(flags, mask){
        console.log('flag secure: ', LayoutParams.FLAG_SECURE.value);
        console.log('before:', flags);
        flags = (flags.value & ~LayoutParams.FLAG_SECURE.value);
        console.log('after:', flags);
        this.call(this, flags, mask);
    };
});
```

<details>
<summary>Output example</summary>
https://stackoverflow.com/a/54818023/2655092
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Shared Preferences update

```javascript
function notifyNewSharedPreference() {
  Java.use('android.app.SharedPreferencesImpl$EditorImpl').putString.overload('java.lang.String', 'java.lang.String').implementation = function(k, v) {
    console.log('[SharedPreferencesImpl]', k, '=', v);
    return this.putString(k, v);
  }
}
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Hook overloads

```javascript
function hookOverloads(className, func) {
  var clazz = Java.use(className);
  var overloads = clazz[func].overloads;
  for (var i in overloads) {
    if (overloads[i].hasOwnProperty('argumentTypes')) {
      var parameters = [];

      var curArgumentTypes = overloads[i].argumentTypes, args = [], argLog = '[';
      for (var j in curArgumentTypes) {
        var cName = curArgumentTypes[j].className;
        parameters.push(cName);
        argLog += "'(" + cName + ") ' + v" + j + ",";
        args.push('v' + j);
      }
      argLog += ']';

      var script = "var ret = this." + func + '(' + args.join(',') + ") || '';\n"
        + "console.log(JSON.stringify(" + argLog + "));\n"
        + "return ret;"

      args.push(script);
      clazz[func].overload.apply(this, parameters).implementation = Function.apply(null, args);
    }
  }
}

Java.perform(function() {
  hookOverloads('java.lang.StringBuilder', '$init');
})
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)


#### Register broadcast receiver

```javascript
Java.perform(() => {
    const MyBroadcastReceiver = Java.registerClass({
        name: 'MyBroadcastReceiver',
        superClass: Java.use('android.content.BroadcastReceiver'),
        methods: {
            onReceive: [{
                returnType: 'void',
                argumentTypes: ['android.content.Context', 'android.content.Intent'],
                implementation: function(context, intent) {
                    // ..
                }
            }]
        },
    });
    let ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    ctx.registerReceiver(MyBroadcastReceiver.$new(), Java.use('android.content.IntentFilter').$new('com.example.JAVA_TO_AGENT'));
});
```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)

#### OS Log

```js
var m = 'libsystem_trace.dylib';
// bool os_log_type_enabled(os_log_t oslog, os_log_type_t type);
var isEnabledFunc = Module.findExportByName(m, 'os_log_type_enabled');
// _os_log_impl(void *dso, os_log_t log, os_log_type_t type, const char *format, uint8_t *buf, unsigned int size);
var logFunc = Module.findExportByName(m, '_os_log_impl');

// Enable all logs
Interceptor.attach(isEnabledFunc, {
  onLeave: function (ret) {
    ret.replace(0x1);
  }
});

Interceptor.attach(logFunc, {
  onEnter: function (a) {
/*
OS_ENUM(os_log_type, uint8_t,
	OS_LOG_TYPE_DEFAULT = 0x00,
	OS_LOG_TYPE_INFO    = 0x01,
	OS_LOG_TYPE_DEBUG   = 0x02,
	OS_LOG_TYPE_ERROR   = 0x10,
	OS_LOG_TYPE_FAULT   = 0x11);
*/
    var type = a[2]; 
    var format = a[3];
    if (type !== 0x2) {
      console.log(JSON.stringify({
        type: type,
        format: format.readCString(),
        //buf: a[4].readPointer().readCString() // TODO
      }, null, 2));
    }
  }
})
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
    var errorPtr = Memory.alloc(Process.pointerSize); 
    Memory.writePointer(errorPtr, NULL); 
    var folders = ObjC.classes.NSFileManager.defaultManager().contentsOfDirectoryAtPath_error_(path_prefix, errorPtr);
    var error = Memory.readPointer(errorPtr);
    if (errorPtr) 
    	console.error( new ObjC.Object( error ) );
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
var cookieJar = {};
var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
for (var i = 0, l = cookies.count(); i < l; i++) {
  var cookie = cookies['- objectAtIndex:'](i);
  cookieJar[cookie.Name()] = cookie.Value().toString(); // ["- expiresDate"]().toString()
}
console.log(JSON.stringify(cookieJar, null, 2));
```

<details>
<summary>Output example</summary>
```js
{
  "key1": "value 1",
  "key2": "value 2"
}
```
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

#### Hook refelaction 
Hooking `objc_msgSend`

```py
import frida, sys

f = open('/tmp/log', 'w')    

def on_message(msg, _data):
    f.write(msg['payload']+'\n')

frida_script = """
  Interceptor.attach(Module.findExportByName('/usr/lib/libobjc.A.dylib', 'objc_msgSend'), {
    onEnter: function(args) {
     var m = Memory.readCString(args[1]);
     if (m != 'length' && !m.startsWith('_fastC'))
        send(m);
    }
  });
"""
device = frida.get_usb_device()
pid = device.spawn(["com.example"]) # or .get_frontmost_application()
session = device.attach(pid)
script = session.create_script(frida_script)
script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```
```sh
$ sort /tmp/log | uniq -c | sort -n
```

<details>
<summary>Output example</summary>
TODO	
</details>

<br>[⬆ Back to top](#table-of-contents)

#### Intercept Entire Module

To reduce UI related functions I ues the following steps:

1. Output log to a file using `-o /tmp/log1`   
2. Copy MRU to excludesList using `$ sort /tmp/log1 | uniq -c | sort -rn | head -n20 | cut -d# -f2 | paste -sd "," -`

```js
var mName = 'MyModule', excludeList = ['Alot', 'Of', 'UI', 'Related', 'Functions'];
Module.enumerateExportsSync(mName)
  .filter(function(e) {
    var fromTypeFunction = e.type == 'function';·
    var notInExcludes = excludeList.indexOf(e.name) == -1;
    return fromTypeFunction && notInExcludes;
  })
  .forEach(function(e) {
    Interceptor.attach(Module.findExportByName(mName, e.name), {
      onEnter: function(args) {
        console.log(mName + "#'" + e.name + "'");
      }
    })
  })
```

<details>
<summary>Output example</summary>
TODO	
</details>

<br>[⬆ Back to top](#table-of-contents)



#### Dump memory segments

```js
Process.enumerateRanges('rw-', {
	onMatch: function (range) {
		var fname = `/sdcard/${range.base}_dump`;
		var f = new File(fname, 'wb');
		f.write(instance.base.readByteArray(instance.size));
		f.flush();
		f.close();
		console.log(`base=${range.base} size=${range.size} prot=${range.protection} fname=${fname}`);
	},
	onComplete: function () {}
});
```

<details>
<summary>Output example</summary>
TODO	
</details>

<br>[⬆ Back to top](#table-of-contents)



#### Memory scan

```js
function memscan(str) {
	Process.enumerateModulesSync().filter(m => m.path.startsWith('/data')).forEach(m => {
		var pattern = str.split('').map(letter => letter.charCodeAt(0).toString(16)).join(' ');
		try {
			var res = Memory.scanSync(m.base, m.size, pattern);
			if (res.length > 0)
				console.log(JSON.stringify({m, res}));
		} catch (e) {
			console.warn(e);
		}
	});
}
```


```js
var memscn = function (str) {
	Process.enumerateModulesSync().forEach(function (m) {
		var pattern = str.split('').map(function (l) { return l.charCodeAt(0).toString(16) }).join(' ');
		try {
			var res = Memory.scanSync(m.base, m.size, pattern);
			if (res.length > 0)
				console.log(JSON.stringify({m, res}, null , 2));
		} catch (e) {
			console.warn(e);
		}
	});
}
```

<details>
<summary>Output example</summary>
pattern [ 52 41 4e 44 4f 4d ] {
  "name": "Test",
  "base": "0x1048fc000",
  "size": 147000,
  "path": "/var/containers/Bundle/Application/CD74EB00-9D90-4600-BF5D-F6E5E0CDF878/Test.app/Test"
}
[{"address":"0x10491f211","size":6}]

</details>

<br>[⬆ Back to top](#table-of-contents)







#### Stalker

```js
  var _module = Process.findModuleByName('myModule');
  var base = ptr(_module.base);
  var startTraceOffset = 0xabcd1234, numInstructionsToTrace = 50;
  var startTrace = base.add(startTraceOffset), endTrace = startTrace.add(4 * (numInstructionsToTrace - 1));
  
  Interceptor.attach(ObjC.classes.CustomClass['- func'].implementation, {
    onEnter: function (args) {
      var tid = Process.getCurrentThreadId();
      this.tid = tid;
      console.warn(`onEnter [ ${tid} ]`);     
      Stalker.follow(tid, {
        transform: function (iterator) {
          var instruction;
          while ((instruction = iterator.next()) !== null) {
            // condition to putCallout
	    if (instruction.address <= endTrace && instruction.address >= startTrace) {     
	      // print instruction & registers values
              iter.putCallout(function(context) {
                var offset = ptr(context.pc).sub(base);
                var inst = Instruction.parse(context.pc).toString();
                var modified_inst = inst;
                inst.replace(/,/g, '').split(' ').forEach(op => {
                  if (op.startsWith('x'))
                    modified_inst = modified_inst.replace(op, context[op]);
                  else if (op.startsWith('w'))
                    modified_inst = modified_inst.replace(op, context[op.replace('w', 'x')]);
                });
                modified_inst = '\x1b[35;01m' + modified_inst + '\x1b[0m';
                console.log(`x8=${context.x8} x25=${context.x25} x0=${context.x0} x21=${context.x21}`)
                console.log(`${offset} ${inst} # ${modified_inst}`);
              });
	    }
	    iterator.keep();
          }
        }
      })
    },  
    onLeave: function (retval) {
      console.log(`onLeave [ ${this.tid} ]`);
      // cleanup
      Stalker.unfollow(this.tid);
      Stalker.garbageCollect();
    }   
  })  
```

<details>
<summary>Output example</summary>
mul x5, x2, x21 # mul 0x3, 0x4, 0x5
</details>

<br>[⬆ Back to top](#table-of-contents)



#### Device properties
Example of quick&dirty iOS device properties extraction

```js
var UIDevice = ObjC.classes.UIDevice.currentDevice();
UIDevice.$ownMethods
  .filter(function(method) { 
    return method.indexOf(':') == -1 /* filter out methods with parameters */
       && method.indexOf('+') == -1 /* filter out public methods */
  })
  .forEach(function(method) { 
    console.log(method, ':', UIDevice[method]())
  })
console.log('executablePath =', ObjC.classes.NSBundle.mainBundle().executablePath().toString());

```

<details>
<summary>Output example</summary>

```
- adjTrackingEnabled : true
- adjFbAttributionId : 
- adjVendorId : 4AAAAAAA-CECC-4BBB-BDDD-DEEEEEEEED18
- adjDeviceType : iPhone
- adjDeviceName : iPhone8,2
- adjCreateUuid : dfaaaa2-ebbd-4ccc-addd-eaeeeeeeee7c
- adjIdForAdvertisers : 7AAAAA3A-4BBB-4CCC-BDDD-0EEEEEEEE8A6
- sbf_bannerGraphicsQuality : 100 
- sbf_controlCenterGraphicsQuality : 100 
- sbf_homeScreenFolderGraphicsQuality : 100 
- sbf_searchTransitionGraphicsQuality : 100 
- sbf_dashBoardPresentationGraphicsQuality : 100 
- sbf_homeScreenBlurGraphicsQuality : 100 
- userInterfaceIdiom : 0 
- _supportsDeepColor : false
- name : iPhone
- _keyboardGraphicsQuality : 100 
- isGeneratingDeviceOrientationNotifications : true
- orientation : 1 
- _backlightLevel : 1 
- isProximityMonitoringEnabled : false
- systemVersion : 11.1.1
- _graphicsQuality : 100 
- beginGeneratingDeviceOrientationNotifications : undefined
- endGeneratingDeviceOrientationNotifications : undefined
- buildVersion : 15C222
- systemName : iOS 
- _isSystemSoundEnabled : true
- _feedbackSupportLevel : 1 
- model : iPhone
- _supportsForceTouch : true
- localizedModel : iPhone
- identifierForVendor : 4A7B44DB-AAAA-BBB-CCC-D8819581DDD
- isBatteryMonitoringEnabled : false
- batteryState : 0 
- batteryLevel : -1
- proximityState : false
- isMultitaskingSupported : true
- playInputClick : undefined
- _softwareDimmingAlpha : 0 
- _playInputSelectSound : undefined
- _playInputDeleteSound : undefined
- _hasGraphicsQualityOverride : false
- _hasTouchPad : false
- _clearGraphicsQualityOverride : undefined
- _predictionGraphicsQuality : 100 
- _nativeScreenGamut : 0 
- _tapticEngine : <_UITapticEngine: 0x1c06257c0>
```

</details>

<br>[⬆ Back to top](#table-of-contents)


#### Take screenshot

```js
function screenshot() {
  ObjC.schedule(ObjC.mainQueue, function() {
    var getNativeFunction = function (ex, retVal, args) {
      return new NativeFunction(Module.findExportByName('UIKit', ex), retVal, args);
    };
    var api = {
      UIWindow: ObjC.classes.UIWindow,
      UIGraphicsBeginImageContextWithOptions: getNativeFunction('UIGraphicsBeginImageContextWithOptions', 'void', [['double', 'double'], 'bool', 'double']),
      UIGraphicsBeginImageContextWithOptions: getNativeFunction('UIGraphicsBeginImageContextWithOptions', 'void', [['double', 'double'], 'bool', 'double']),
      UIGraphicsEndImageContext: getNativeFunction('UIGraphicsEndImageContext', 'void', []),
      UIGraphicsGetImageFromCurrentImageContext: getNativeFunction('UIGraphicsGetImageFromCurrentImageContext', 'pointer', []),
      UIImagePNGRepresentation: getNativeFunction('UIImagePNGRepresentation', 'pointer', ['pointer'])
    };
    var view = api.UIWindow.keyWindow();
    var bounds = view.bounds();
    var size = bounds[1];
    api.UIGraphicsBeginImageContextWithOptions(size, 0, 0);
    view.drawViewHierarchyInRect_afterScreenUpdates_(bounds, true);

    var image = api.UIGraphicsGetImageFromCurrentImageContext();
    api.UIGraphicsEndImageContext();

    var png = new ObjC.Object(api.UIImagePNGRepresentation(image));
    send('screenshot', Memory.readByteArray(png.bytes(), png.length()));
  });
}

rpc.exports = {
  takescreenshot: screenshot
}
```

```py
...
def save_screenshot(d):
    f = open('/tmp/screenshot.png', 'wb')
    f.write(d)
    f.close()

def on_message(msg, data):
    save_screenshot(data)
 
 script.exports.takescreenshot()
 
 # open screenshot & invoke rpc via input 
 # <Ctrl+C> will take screenshot, open it with eog & wait for export function name to invoke via input
 def on_message(msg, data):
    if 'payload' in msg:
        if msg['payload'] == 'screenshot':
            i = '/tmp/screenshot.png'
            f = open(i, 'wb')
            f.write(data)
            f.close()
            subprocess.call(['eog', i])
	   
 while True:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        script.exports.takescreenshot()
        try:
            getattr(script.exports, input())()
        except (KeyboardInterrupt, frida.core.RPCException) as e:
            print('[!]', e)

```

<details>
<summary>Output example</summary>
TODO
</details>

<br>[⬆ Back to top](#table-of-contents)



#### TODOs 
- Add GIFs & examples
- Add links to /scripts
- Extend universal SSL unpinning for [ios](https://codeshare.frida.re/@dki/ios10-ssl-bypass/) [andoid 1](https://github.com/Fuzion24/JustTrustMe/blob/master/app/src/main/java/just/trust/me/Main.java) [android 
