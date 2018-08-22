var isLibARThooked = false;

function hookLibART() {
    if (isLibARThooked === true) {
        return;
    }
    var symbols = Module.enumerateSymbolsSync("libart.so");
    var addrRegisterNativeMethods;
    var jclassAddress2NameMap = {};
    for (i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        switch (symbol.name) {
            case "_ZN3art3JNI21RegisterNativeMethodsEP7_JNIEnvP7_jclassPK15JNINativeMethodib":
                /*
                    _ZN3art3JNI21RegisterNativeMethodsEP7_JNIEnvP7_jclassPK15JNINativeMethodib
                    https://demangler.com/
                    art::JNI::RegisterNativeMethods(_JNIEnv*, _jclass*, JNINativeMethod const*, int, bool)
                */
                addrRegisterNativeMethods = symbol.address;
                console.log("RegisterNativeMethods is at " + addrRegisterNativeMethods);
                Interceptor.attach(addrRegisterNativeMethods, {
                    onEnter: function(args) {
                        var methodsPtr = ptr(args[2]);
                        var methodCount = parseInt(args[3]);
                        for (var i = 0; i < methodCount; i++) {
                            var namePtr = Memory.readPointer(methodsPtr.add(i * 12));
                            var sigPtr = Memory.readPointer(methodsPtr.add(i * 12 + 4));
                            var fnPtrPtr = Memory.readPointer(methodsPtr.add(i * 12 + 8));
                            // output schema: className#methodName(arguments)returnVal@address
                            console.log(
                                jclassAddress2NameMap[args[0]].replace(/\//g, '.') +
                                '#' + Memory.readCString(namePtr) +
                                Memory.readCString(sigPtr) +
                                '@' + fnPtrPtr
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
    }

    isLibARThooked = true;
}

Java.perform(function () {
    try {
        hookLibART();
    } catch (e) {
        // safety first
        console.error('[?]', e);
    }
});
