# Check for native library calls and return a stacktrace
import sys
import frida
from pprint import pprint


def on_message(m, _data):
    if m['type'] == 'send':
        print(m['payload'])
    else:
        if m['type'] == 'error':
            pprint(m)
            exit(2)


jscode = """
Java.perform(function() {

    var SystemDef = Java.use('java.lang.System');

    var RuntimeDef = Java.use('java.lang.Runtime');

    var exceptionClass = Java.use('java.lang.Exception');

    var SystemLoad_1 = SystemDef.load.overload('java.lang.String');

    var SystemLoad_2 = SystemDef.loadLibrary.overload('java.lang.String');

    var RuntimeLoad_1 = RuntimeDef.load.overload('java.lang.String');

    var RuntimeLoad_2 = RuntimeDef.loadLibrary.overload('java.lang.String');

    var ThreadDef = Java.use('java.lang.Thread');

    var ThreadObj = ThreadDef.$new();

    SystemLoad_1.implementation = function(library) {
        send("[1] Loading dynamic library => " + library);
        stackTrace();
        return SystemLoad_1.call(this, library);
    }

    SystemLoad_2.implementation = function(library) {
        send("[2] Loading dynamic library => " + library);
        stackTrace();
        SystemLoad_2.call(this, library);
        return;
    }

    RuntimeLoad_1.implementation = function(library) {
        send("[3] Loading dynamic library => " + library);
        stackTrace();
        RuntimeLoad_1.call(this, library);
        return;
    }

    RuntimeLoad_2.implementation = function(library) {
        send("[4] Loading dynamic library => " + library);
        stackTrace();
        RuntimeLoad_2.call(this, library);
        return;
    }

    function stackTrace() {
        var stack = ThreadObj.currentThread().getStackTrace();
        for (var i = 0; i < stack.length; i++) {
            send(i + " => " + stack[i].toString());
        }
        send("--------------------------------------------------------------------------");
    }

});
"""
APP = 'com.app'
device = frida.get_usb_device()
pid = device.spawn([APP])
session = device.attach(pid)
script = session.create_script(jscode)
print("[*] Intercepting [{}]".format(pid))
script.on('message', on_message)
script.load()
device.resume(APP)
sys.stdin.read()
