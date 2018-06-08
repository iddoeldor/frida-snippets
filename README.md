# Contents
 - [Enumerate loaded classes](#enumerate-loaded-classes) 
 - [Extract modules from APK](#extract-modules-from-apk) 
 - [Get methods from .so file](#get-methods-from-so-file)
 - [SQLite hook example](#sqlite-hook)
 - [Hook Java refelaction](#hook-refelaction)
 - [Hook constructor](#hook-constructor)
 - [Hook JNI](#hook-jni)
 - [Print all runtime strings & Stacktrace](#print-runtime-strings)
 - [Find iOS application UUID](#find-ios-application-uuid)
 - [Execute shell command](#execute-shell-command)
 - [TODO list](#todos)
 
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
#### Hook JNI
Hook native method and print arguments
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
#### Print runtime strings 
Print created StringBuilder & StringBuffer & Stacktrace
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
#### Find iOS application UUID 
Get UUID for specific path when attached to an app
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

#### Execute shell command
```
"""
Execute shell command
For example, list directory contents:
def ls(folder):
    cmd = Shell(['/bin/sh', '-c', 'ls -la ' + folder], None)
    cmd.exec()
    for chunk in cmd.output:
        print(chunk.strip().decode())
"""
import frida
from frida.application import Reactor
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
        # if len(data) > 0:
            # print("⚡ output: pid={}, fd={}, data={}".format(pid, fd, repr(data)))
        self.output.append(data)

    def _on_detached(self, pid, session, reason):
        click.secho("⚡ detached: pid={}, reason='{}'".format(pid, reason), fg='green', dim=True)
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    @staticmethod
    def _on_message(pid, message):
        click.secho("⚡ message: pid={}, payload={}".format(pid, message), fg='green', dim=True)
```

#### TODOs 
- Add GIFs & docs

- References overview:
* https://techblog.mediaservice.net/2017/09/tracing-arbitrary-methods-and-function-calls-on-android-and-ios/
* https://zhiwei.li/text/2016/02/01/%E7%BC%96%E8%AF%91frida/
* https://kov4l3nko.github.io/blog/2018-05-27-sll-pinning-hook-sectrustevaluate/
