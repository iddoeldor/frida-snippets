/*
TODO test if no need to compile again the method

mono_object_get_virtual_method (obj, method);

we need to free the result from mono_string_to_utf8 ()
mono_free (p)


MonoObject
https://github.com/mono/mono/blob/master/samples/embed/test-invoke.c#L284
*/
/*
. Button to install Frida on (rooted) Android device and start via ADB
. Select app to hook
. spawn app
. if it not uses mono:
        alert: "we hook Unity3d/Mono/Xamarin, this app seems to not use it..
                Xamarin is a Microsoft-owned software company founded in May 2011 by the engineers that created Mono,
                Mono for Android and MonoTouch, which are cross-platform implementations of the Common Language
                Infrastructure (CLI) and Common Language Specifications (often called Microsoft .NET).
else:
	. hook dlopen, send Assembly-CSharp.dll to python side & save
	. extract methods descriptions (name, arguments, return value, full signature) (w/ frida or static tool?)
	. let user select one or many methods to hook
		. for each methods selected, open select box to select which arguments to print or save into CSV
	. add exit button to unload frida and de-attach

* https://kivy.org	
*/

// https://github.com/freehuntx/frida-mono-api/blob/master/src/mono-api-helper.js#L21
// https://github.com/freehuntx/frida-mono-api/blob/master/src/mono-api-helper.js#L53
// https://github.com/freehuntx/frida-mono-api/blob/master/src/mono-api-helper.js#L34
// https://github.com/freehuntx/frida-mono-api/blob/master/src/mono-api-helper.js#L18

// await until Mono is loaded
var awaitForCondition = function(callback) {
    var int = setInterval(function() {
        if (Module.findExportByName(null, "mono_get_root_domain")) {
            clearInterval(int);
            callback();
            return;
        }
    }, 0);
}

function cb(funcName) {
    return {
        onEnter: function(args) {
            this.extra = {
                funcName: funcName,
                arg0: args[0]
            };
        },
        onLeave: function(retval) {
            this.extra.retval = retval;
            console.log(JSON.stringify(this.extra, null, 2));
            console.log( hexdump(retval, { offset: 0, length: 0x60, header: true, ansi: true }) );
        }
    }
}

function hookMethod(dll, name_space, klass, method, num_params, extra) {
//    var monoImage = mono_image_loaded(dll);
    // monoImage will be the same as this.extra.image
    var monoClass = mono_class_from_name(extra.image, name_space, klass);
    var monoMethod = mono_class_get_method_from_name(monoClass, method, num_params);
    // = mono_class_get_method_from_name(monoClass, "lastRecivedGameId", -1); // mono_class_get_field
    var compiledMethod = mono_compile_method(monoMethod);

    Interceptor.attach(monoMethod, cb("monoMethod"));
    Interceptor.attach(compiledMethod, cb("compiledMethod"));

    Object.assign(extra, {
        //MonoImage: monoImage,
        MonoClass: monoClass,
        monoMethod: monoMethod,
        compiledMethod: compiledMethod
    });
    console.log(JSON.stringify(extra, null, 2));
}

function hook() {
    Interceptor.attach(Module.findExportByName(null, "mono_assembly_load_from_full"), {
        onEnter: function(args) {
            this.extra = {
                image: args[0],
                fname: Memory.readUtf8String(args[1]),
                status: args[2],
                refonly: args[3],
            };
        },
        onLeave: function(retval) {
            if (this.extra.fname.endsWith("Assembly-CSharp.dll")) {
                this.extra.retval = retval;
                hookMethod(this.extra.fname, "", "NetworkDriver", "AskForQuestion", -1, this.extra);
            }
        }
    });
    /*
    Interceptor.attach(Module.findExportByName(null, "mono_class_from_name"), {
        onEnter: function(args) {
            this.extra = {
                name_space: Memory.readUtf8String(args[1]),
                name: Memory.readUtf8String(args[2])
            };
        },
        onLeave: function(retval) {
            if (this.extra.name_space.indexOf("UnityEngine.UI") != -1) {
                console.log(JSON.stringify(this.extra, null, 2));
            }
        }
    });
    */
}

/**
* MonoImage* mono_image_loaded (const char *name)
* http://docs.go-mono.com/index.aspx?link=xhtml%3Adeploy%2Fmono-api-image.html
*/
var mono_image_loaded = function(name) {
    return new NativeFunction(
        Module.findExportByName(null, "mono_image_loaded"), // pointer to method
        'pointer', // return type, MonoImage*
        ['pointer'] // arguments, char *name
    )(
        Memory.allocUtf8String(name) // allocating & passing parameter's address
    )
}

/**
* MonoClass* mono_class_from_name (MonoImage *image, const char* name_space, const char *name)
* http://docs.go-mono.com/?link=api%3amono_class_from_name
*/
var mono_class_from_name = function(image, name_space, name) {
    return new NativeFunction(
        Module.findExportByName(null, "mono_class_from_name"),
        'pointer',
        ['pointer', 'pointer', 'pointer']
    )( image, Memory.allocUtf8String(name_space), Memory.allocUtf8String(name) )
}

/**
* MonoMethod* mono_class_get_method_from_name (MonoClass *klass, const char *name, int param_count)
*   klass	where to look for the method
*   name	name of the method
*   param_count	number of parameters. -1 for any number.
* http://docs.go-mono.com/index.aspx?link=xhtml%3Adeploy%2Fmono-api-class.html
*/
var mono_class_get_method_from_name = function(klass, name, param_count) {
    return new NativeFunction(
        Module.findExportByName(null, "mono_class_get_method_from_name"),
        'pointer',
        ['pointer', 'pointer', 'int']
    )( klass, Memory.allocUtf8String(name), param_count )
}

/**
* gpointer mono_compile_method (MonoMethod *method)
* http://docs.go-mono.com/index.aspx?link=xhtml%3Adeploy%2Fmono-api-unsorted.html
*/
var mono_compile_method = function(method) {
    return new NativeFunction(
        Module.findExportByName(null, "mono_compile_method"),
        'pointer',
        ['pointer']
    )( method )
}

//////////////// Main ////////////////
Java.perform(awaitForCondition(hook));



































/*
1. Get image by name [call mono_image_loaded]
2. Get class by name [call mono_class_from_name](#http://docs.go-mono.com/?link=api%3amono_class_from_name)
3. Get method in class by name [call mono_class_get_method_from_name](#http://docs.go-mono.com/index.aspx?link=xhtml%3Adeploy%2Fmono-api-class.html)
4. Compile method to get address [call mono_compile_method](#http://docs.go-mono.com/index.aspx?link=xhtml%3Adeploy%2Fmono-api-unsorted.html)
5. Intercept compiled method
*/
function Main() {
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
		this._image = args[0];
		this._fname = Memory.readUtf8String(args[1]);
		this._status = args[2];
		this._refonly = args[3];
                console.log('[E]', args[0], Memory.readUtf8String(args[1]));
            },
            onLeave: function(retval) {
                if (this._fname.indexOf("Assembly-CSharp.dll") != -1) {
			console.log("mono_class_from_name", Module.findExportByName(null, "mono_class_from_name") );	
			Interceptor.attach(Module.findExportByName(null, "mono_class_from_name"), {
				onEnter: function(args) {
					var name_space = Memory.readUtf8String(args[1]).toString();
					if (
						!name_space.startsWith("System") && 
						!name_space.startsWith("Unity") && 
						!name_space.startsWith("Facebook") && 
						!name_space.startsWith("Google")
					) {
						console.log('[E2]', args[0], name_space, Memory.readUtf8String(args[2]) );
						this._namespace = name_space;
					}
					else this._namespace = null;
				},
				onLeave: function(retval) {
					if (this._namespace) console.log('[L2]', this._namespace, retval);
				}
			});	
		}
            }
        });

    }
    awaitForCondition(hook);
}
Java.perform(Main);






















// apk/assets/bin/Data/Managed$ for i in *.dll; do echo "[*] $i"; rabin2 -zzz $i | grep -i certificate; done

Java.perform(function() {

    var awaitForCondition = function(callback) {
        var int = setInterval(function() {
            if (Module.findExportByName(null, "mono_get_root_domain")) {
                clearInterval(int);
                callback();
                return;
            }
        }, 0);
    }

    function hookSet() {
        Interceptor.attach(Module.findExportByName(null, "mono_assembly_load_from_full"), {
            onEnter: function(args) {
                var name = Memory.readUtf8String(ptr(args[1]));
                console.log('[1]', name);
                var parts = name.split('/');
                if (parts.length < 2) {
                    parts = name.split(',');
                }
                var dllName = parts[parts.length - 1];
                this.dllName = dllName;
            },
            onLeave: function(retval) {
                if (this.dllName == 'Assembly-CSharp.dll') {
                    console.log('[2]', retval, this.dllName);
                    console.log('[3]', Module.enumerateSymbolsSync(this.dllName));
                }
            }
        });
    }
    awaitForCondition(hookSet);

});







function binary2hex2ascii(array, readBytesNum) {
    var result = [];
    // performance wise to read 100 bytes
    readBytesNum = readBytesNum || 100;
    for (var i = 0; i < readBytesNum; ++i) {
    // TODO fix unicode for Hebrew and Math related symbols
    // * (double) doesn't work, but + (plus) works
        result.push(String.fromCharCode(
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16) ).slice(-2), // binary2hex part
                16
            )
        ));
    }
    // TODO extract facebookID from previous_winners packet, #OSINT ?
    return result.join('');
}

function hookInputStream() {
    Java.use('java.io.InputStream').read.overload('[B').implementation = function(b) {
        var retval = this.read(b);
        var resp = binary2hex2ascii(b);
        // conditions to not print garbage packets
        if (
            resp.indexOf('isBot') == -1
            && resp.indexOf(' Answer') == -1
            && resp.indexOf('Pinged') == -1
        ) {
            console.log( resp );
        }
        if (resp.indexOf('Waiting To Show Question') != -1) {
            console.log("\n\n\t{{ " + binary2hex2ascii( b , 1200) + " }}\n\n");
        }
        // TODO mimic answer packet (hook OutputStream), send to get back the answer
        return retval;
    };
}

function hookOutputStream() {
    var bClass = Java.use("java.io.OutputStream");
    bClass.write.overload('int').implementation = function(x) {
        console.log("[1] " + x);
        return this.write(x);
    }
    bClass.write.overload('[B').implementation = function(b) {
        console.log("[2] " + binary2hex2ascii(b) );
        return this.write(b);
    }
    bClass.write.overload('[B','int','int').implementation = function(b,y,z) {
        console.log("[3] " + binary2hex2ascii(b));
        return this.write(b,y,z);
    }
}

function hookConstructor() {
    var Map = Java.use('java.util.Map');
    Java.use('com.unity3d.player.UnityWebRequest').$init
        .overload('long', 'java.lang.String', 'java.util.Map', 'java.lang.String', 'int').implementation = function(long1, str2, map3, str4, int5) {
        console.log(this, JSON.stringify({
            '#1': long1,
            method: str2,
            headers: Java.cast(map3, Map).toString(),
            url: str4,
            '#5': int5
        }, null, 2));
        this.$init(long1, str2, map3, str4, int5);
    };
}

function hookUploadCallback() {
    Java.use('com.unity3d.player.UnityWebRequest').uploadCallback.overload('java.nio.ByteBuffer').implementation = function(buf1) {
        console.log('uploadCallback', buf1);
        this.uploadCallback(buf1);
    };
}


function traceClass(targetClass) {
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose;

	var parsedMethods = [];
	methods.forEach(function(method) {
		parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
	});

	var targets = uniqBy(parsedMethods, JSON.stringify);
	targets.forEach(function(targetMethod) {
		traceMethod(targetClass + "." + targetMethod);
	});
}

function traceMethod(targetClassMethod) {
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;
	console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");
	for (var i = 0; i < overloadCount; i++) {
		hook[targetMethod].overloads[i].implementation = function() {
			console.warn("\n*** entered " + targetClassMethod);

			// print backtrace
			// Java.perform(function() {
			//	var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
			//	console.log("\nBacktrace:\n" + bt);
			// });

			// print args
			if (arguments.length) console.log();
			for (var j = 0; j < arguments.length; j++) {
				console.log("arg[" + j + "]: " + arguments[j]);
			}

			// print retval
			var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
			console.log("\nretval: " + retval);
			console.warn("\n*** exiting " + targetClassMethod);
			return retval;
		}
	}
}

function uniqBy(array, key) { // remove duplicates from array
    var seen = {};
    return array.filter(function(item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}

function trace(pattern)
{
	var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";

	if (type === "module") {

		// trace Module
		var res = new ApiResolver("module");
		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);
		targets.forEach(function(target) {
			traceModule(target.address, target.name);
		});

	} else if (type === "java") {

		// trace Java Class
		var found = false;
		Java.enumerateLoadedClasses({
			onMatch: function(aClass) {
				if (aClass.match(pattern)) {
					found = true;
					var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
					traceClass(className);
				}
			},
			onComplete: function() {}
		});

		// trace Java Method
		if (!found) {
			try {
				traceMethod(pattern);
			}
			catch(err) { // catch non existing classes/methods
				console.error(err);
			}
		}
	}
}

function traceModule(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = false;
			// var filename = Memory.readCString(ptr(args[0]));
			// if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) // exclusion list
			// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
				this.flag = true;

			if (this.flag) {
				console.warn("\n*** entered " + name);

				// print backtrace
				console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n"));
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				// print retval
				console.log("\nretval: " + retval);
				console.warn("\n*** exiting " + name);
			}
		}

	});
}

// Main
Java.perform(function() {
    try {
//        hookInputStream();
//        hookOutputStream();
//        hookConstructor();
//        hookUploadCallback();
// https://blogs.unity3d.com/2014/06/11/all-about-the-unity-networking-transport-layer/
//        traceClass('com.unity3d.player.WWW');
//        trace("exports:*!*send*"); // Tracing /system/lib/libnetutils.so!send_packet
//        trace("exports:*!*packet*");
        /*
        Tracing /system/lib/libnetutils.so!send_packet
        Tracing /system/lib/libnetutils.so!receive_packet
        // but no logs
        */
//        Interceptor.attach(Module.findExportByName('/system/lib/libnetutils.so', 'send_packet'), {
//            onEnter: function(args) {
//                console.log('send_packet', args[0]);
//            },
//            onLeave: function(retval) {
//            }
//        });
    } catch (e) {
        console.error(e);
    }
});









































function binary2hex2ascii(array, readBytesNum) {
    var result = [];
    // performance wise to read 100 bytes
    readBytesNum = readBytesNum || 100;
    for (var i = 0; i < readBytesNum; ++i) {
    // TODO fix unicode for Hebrew and Math related symbols
    // * (double) doesn't work, but + (plus) works
        result.push(String.fromCharCode(
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16) ).slice(-2), // binary2hex part
                16
            )
        ));
    }
    // TODO extract facebookID from previous_winners packet, #OSINT ?
    return result.join('');
}

function hookInputStream() {
    Java.use('java.io.InputStream').read.overload('[B').implementation = function(b) {
        var retval = this.read(b);
        var resp = binary2hex2ascii(b);
        // conditions to not print garbage packets
        if (
            resp.indexOf('isBot') == -1
            && resp.indexOf(' Answer') == -1
            && resp.indexOf('Pinged') == -1
        ) {
            console.log( resp );
        }
        if (resp.indexOf('Waiting To Show Question') != -1) {
            console.log("\n\n\t{{ " + binary2hex2ascii( b , 1200) + " }}\n\n");
        }
        // TODO mimic answer packet (hook OutputStream), send to get back the answer
        return retval;
    };
}

function hookOutputStream() {
    var bClass = Java.use("java.io.OutputStream");
    bClass.write.overload('int').implementation = function(x) {
        console.log("[1] " + x);
        return this.write(x);
    }
    bClass.write.overload('[B').implementation = function(b) {
        console.log("[2] " + binary2hex2ascii(b) );
        return this.write(b);
    }
    bClass.write.overload('[B','int','int').implementation = function(b,y,z) {
        console.log("[3] " + binary2hex2ascii(b));
        return this.write(b,y,z);
    }
}

function hookConstructor() {
    var Map = Java.use('java.util.Map');
    Java.use('com.unity3d.player.UnityWebRequest').$init
        .overload('long', 'java.lang.String', 'java.util.Map', 'java.lang.String', 'int').implementation = function(long1, str2, map3, str4, int5) {
        console.log(this, JSON.stringify({
            '#1': long1,
            method: str2,
            headers: Java.cast(map3, Map).toString(),
            url: str4,
            '#5': int5
        }, null, 2));
        this.$init(long1, str2, map3, str4, int5);
    };
}

function hookUploadCallback() {
    Java.use('com.unity3d.player.UnityWebRequest').uploadCallback.overload('java.nio.ByteBuffer').implementation = function(buf1) {
        console.log('uploadCallback', buf1);
        this.uploadCallback(buf1);
    };
}


function traceClass(targetClass) {
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose;

	var parsedMethods = [];
	methods.forEach(function(method) {
		parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
	});

	var targets = uniqBy(parsedMethods, JSON.stringify);
	targets.forEach(function(targetMethod) {
		traceMethod(targetClass + "." + targetMethod);
	});
}

function traceMethod(targetClassMethod) {
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;
	console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");
	for (var i = 0; i < overloadCount; i++) {
		hook[targetMethod].overloads[i].implementation = function() {
			console.warn("\n*** entered " + targetClassMethod);

			// print backtrace
			// Java.perform(function() {
			//	var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
			//	console.log("\nBacktrace:\n" + bt);
			// });

			// print args
			if (arguments.length) console.log();
			for (var j = 0; j < arguments.length; j++) {
				console.log("arg[" + j + "]: " + arguments[j]);
			}

			// print retval
			var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
			console.log("\nretval: " + retval);
			console.warn("\n*** exiting " + targetClassMethod);
			return retval;
		}
	}
}

function uniqBy(array, key) { // remove duplicates from array
    var seen = {};
    return array.filter(function(item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}

// Main
Java.perform(function() {
    try {
//        hookInputStream();
//        hookOutputStream();
//        hookConstructor();
//        hookUploadCallback();
// https://blogs.unity3d.com/2014/06/11/all-about-the-unity-networking-transport-layer/
        traceClass('com.unity3d.player.WWW');
    } catch (e) {
        console.error(e);
    }
});



































function binary2hex2ascii(array, readBytesNum) {
    var result = [];
    // performance wise to read 100 bytes
    readBytesNum = readBytesNum || 100;
    for (var i = 0; i < readBytesNum; ++i) {
    // TODO fix unicode for Hebrew and Math related symbols
    // * (double) doesn't work, but + (plus) works
        result.push(String.fromCharCode(
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16) ).slice(-2), // binary2hex part
                16
            )
        ));
    }
    // TODO extract facebookID from previous_winners packet, #OSINT ?
    return result.join('');
}

function hookInputStream() {
    Java.use('java.io.InputStream').read.overload('[B').implementation = function(b) {
        var retval = this.read(b);
        var resp = binary2hex2ascii(b);
        // conditions to not print garbage packets
        if (
            resp.indexOf('isBot') == -1
            && resp.indexOf(' Answer') == -1
            && resp.indexOf('Pinged') == -1
        ) {
            console.log( resp );
        }
        if (resp.indexOf('Waiting To Show Question') != -1) {
            console.log("\n\n\t{{ " + binary2hex2ascii( b , 1200) + " }}\n\n");
        }
        // TODO mimic answer packet (hook OutputStream), send to get back the answer
        return retval;
    };
}

function hookOutputStream() {
    var bClass = Java.use("java.io.OutputStream");
    bClass.write.overload('int').implementation = function(x) {
        console.log("[1] " + x);
        return this.write(x);
    }
    bClass.write.overload('[B').implementation = function(b) {
        console.log("[2] " + binary2hex2ascii(b) );
        return this.write(b);
    }
    bClass.write.overload('[B','int','int').implementation = function(b,y,z) {
        console.log("[3] " + binary2hex2ascii(b));
        return this.write(b,y,z);
    }
}

function hookConstructor() {
    var Map = Java.use('java.util.Map');
    Java.use('com.unity3d.player.UnityWebRequest').$init
        .overload('long', 'java.lang.String', 'java.util.Map', 'java.lang.String', 'int').implementation = function(long1, str2, map3, str4, int5) {
        console.log(this, JSON.stringify({
            '#1': long1,
            method: str2,
            headers: Java.cast(map3, Map).toString(),
            url: str4,
            '#5': int5
        }, null, 2));
        this.$init(long1, str2, map3, str4, int5);
    };
}

function hookUploadCallback() {
    Java.use('com.unity3d.player.UnityWebRequest').uploadCallback.overload('java.nio.ByteBuffer').implementation = function(buf1) {
        console.log('uploadCallback', buf1);
        this.uploadCallback(buf1);
    };
}

// Main
Java.perform(function() {

//    hookInputStream();
    hookOutputStream();
//    hookConstructor();
//    hookUploadCallback();

});
    /*
    ! not invoked !
    var oClass = Java.use('java.io.OutputStreamWriter');
    oClass.write.overload('java.lang.String', 'int', 'int').implementation = function(s, i2, i3) {
        console.log('[4]');
        this.write(s, i2, i3);
    };
    oClass.write.overload('[C', 'int', 'int').implementation = function(c, i2, i3) {
        console.log('[5]');
        this.write(c, i2, i3);
    };
    oClass.write.overload('int').implementation = function(i) {
        console.log('[6]');
        this.write(i);
    };
    */











































function binary2hex2ascii(array, readBytesNum) {
    var result = [];
    // performance wise to read 100 bytes
    readBytesNum = readBytesNum || 100;
    for (var i = 0; i < readBytesNum; ++i) {
    // TODO fix unicode for Hebrew and Math related symbols
    // * (double) doesn't work, but + (plus) works
        result.push(String.fromCharCode(
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16) ).slice(-2), // binary2hex part
                16
            )
        ));
    }
    // TODO extract facebookID from previous_winners packet, #OSINT ?
    return result.join('');
}

Java.perform(function() {

    Java.use('java.io.InputStream').read.overload('[B').implementation = function(b) {
        var retval = this.read(b);
        var resp = binary2hex2ascii(b);
        // conditions to not print garbage packets
        if (
            resp.indexOf('isBot') == -1
            && resp.indexOf(' Answer') == -1
            && resp.indexOf('Pinged') == -1
        ) {
            console.log( resp );
        }
        if (resp.indexOf('Waiting To Show Question') != -1) {
            console.log("\n\n\t{{ " + binary2hex2ascii( b , 1200) + " }}\n\n");
        }
        // TODO mimic answer packet (hook OutputStream), send to get back the answer
        return retval;
    };

});


/*
{"status":"Success","gameState":"Waiting To Show Question","questionIndex":0,"gameID":"5b575b2bd3bff
******************************



{"status":"Success","gameState":"Waiting To Show Question","questionIndex":0,"gameID":"5b575b2bd3bff500048c6e91","player1":{"_id":"5b5617b69e848a00044765df","name":"test","facebookID":"","botImage":null,"points":3490,"characterIndex":0,"accuracy":71.54500693523188,"crowns":7},"player2":{"_id":"5a1d866a700dd2000431659d","name":"Zion A","facebookID":"","botImage":"https://s3-eu-west-1.amazonaws.com/data.dbrain.co.il/lhjkaf61mc81/questions/gar/group2/Zion A.jpg","points":13910,"characterIndex":-1,"accuracy":75,"crowns":3007}}



{"status":"Success","gameState":"Waiting For One Answer","lastQuestionIndex":-1}

{"status":"Success","gameState":"Waiting For One Answer","lastQuestionIndex":-1}

{"status":"Success","secondsSinceOtherUserPinged":0.184}

{"status":"Success","gameState":"Waiting For One Answer","lastQuestionIndex":-1}
OK


{"status":"Success","gameState":"Waiting For One Answer","lastQuestionIndex":-1}

{"status":"Success","gameState":"Waiting To Show Question","lastQuestionIndex":0,"lastQuestion":{"qu
******************************



{"status":"Success","secondsSinceOtherUserPinged":0.536}

{"status":"Success","gameState":"Waiting To Show Question","lastQuestionIndex":0,"lastQuestion":{"questionID":"sport_0000000348","question":"ÃÂÃÂÃÂ ÃÂ¡ÃÂÃÂÃÂ ÃÂÃÂªÃÂÃÂÃÂÃÂ§ÃÂ ÃÂ©ÃÂÃÂ ÃÂÃÂ ÃÂÃÂ© ÃÂÃÂÃÂ¨ÃÂÃÂÃÂªÃÂÃÂÃÂ?","answer":3,"answerFromPlayer1":3,"accuracyFromPlayer1":100,"answerFromPlayer2":3,"accuracyFromPlayer2":100,"answerForBotValue":3,"answerForBotTime":10,"secondsTookToAnswerPlayer1":7.131}}


{"status":"Success","gameState":"Waiting To Show Question","lastQuestionIndex":1,"lastQuestion":{"qu
******************************



{"status":"Error: Trying to answer wrong question"}

{"status":"Success","gameState":"Waiting To Show Question","lastQuestionIndex":1,"lastQuestion":{"questionID":"israeli_music_0000000015","question":"ÃÂÃÂÃÂ§ÃÂª ÃÂ¨ÃÂÃÂ§ ÃÂÃÂ©ÃÂ¨ÃÂÃÂÃÂÃÂª: ÃÂ§ÃÂ¨ÃÂ _","answer":9,"answerFromPlayer1":9,"accuracyFromPlayer1":100,"answerFromPlayer2":9,"accuracyFromPlayer2":100,"answerForBotValue":9,"answerForBotTime":7,"secondsTookToAnswerPlayer1":5.98}}

*/
/*
    Java.use('java.nio.ByteBuffer').wrap.overload('[B').implementation = function(byteArr) {
        console.log('*', byteArr.toString());
        console.log('**', Object.getOwnPropertyNames(byteArr.__proto__).join('\n\t'));
        return this.wrap(byteArr);
    };
        console.log(hexdump(Memory.readByteArray(ptr(buf1.$handle), 32), {offset: 0, length: 32, header: true, ansi: true}));
            buf3: buf1.asCharBuffer().toString(),
            np: Memory.readByteArray(ptr(buf1.$handle), 64),
            retval: retval,

    var Map = Java.use('java.util.Map');
    var UnityWebRequest = Java.use('com.unity3d.player.UnityWebRequest');

    UnityWebRequest.downloadCallback.overload('java.nio.ByteBuffer', 'int').implementation = function(buf1, int2) {
        var retval = this.downloadCallback(buf1, int2);
        console.log('downloadCallback', JSON.stringify({
            buf1: buf1.toString(),
            int2: int2
        }, null, '  '));
        return retval;
    };


    var bClass = Java.use("java.io.OutputStream");
    bClass.write.overload('int').implementation = function(x) {
        console.log("[1] " + x);
        return this.write(x);
    }
    bClass.write.overload('[B').implementation = function(b) {
        console.log("[2] " + hex2string( bytes2hex( b ) ) );
        return this.write(b);
    }
    bClass.write.overload('[B','int','int').implementation = function(b,y,z) {
        console.log("[3] " + hex2string( bytes2hex( b ) ) + " | " + y + " | " + z);
        return this.write(b,y,z);
    }
    var ReadableByteChannel = Java.use('java.nio.channels.ReadableByteChannel');
    ReadableByteChannel.read.overload('java.nio.ByteBuffer').implementation = function(b) {
        console.log('arg1', b);
        var retval = this.read(b);
        console.log('retval', retval);
        return retval;
    };


    UnityWebRequest.headerCallback.overload('java.util.Map').implementation = function(map1) {
        console.log('headerCallback', Java.cast(map1, Map).toString());
        this.headerCallback(map1);
    };
    UnityWebRequest.headerCallback.overload('java.lang.String', 'java.lang.String').implementation = function(s1, s2) {
        console.log('headerCallback', s1, s2);
        this.headerCallback(s1, s2);
    };
    UnityWebRequest.uploadCallback.overload('java.nio.ByteBuffer').implementation = function(buf1) {
        console.log('uploadCallback', buf1);
        this.uploadCallback(buf1);
    };

    Java.use('javax.net.ssl.HttpsURLConnection')['setSSLSocketFactory'].overload('javax.net.ssl.SSLSocketFactory').implementation = function(s) {
        console.log('invoked!', s);
        return this.setSSLSocketFactory(null);
    };
    Java.use('javax.net.ssl.SSLContext')['init']
    .overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
    .implementation = function(a1, a2, a3) {
        console.log('invoked!', a1, a2, a3);
        return this.init(null, null, null);
    };
*/























function bytes2hex(array) {
    var result = '';
//    console.log('len = ' + array.length);
    for (var i = 0; i < array.length; ++i) {
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    }
    return result;
}

function hex2string(hex) {
    var string = '';
    for (var i = 0; i < hex.length; i += 2) {
      string += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return string;
}

Java.perform(function() {
//    var Map = Java.use('java.util.Map');
//    var UnityWebRequest = Java.use('com.unity3d.player.UnityWebRequest');
//
//    UnityWebRequest.downloadCallback.overload('java.nio.ByteBuffer', 'int').implementation = function(buf1, int2) {
//        var retval = this.downloadCallback(buf1, int2);
//        console.log('downloadCallback', JSON.stringify({
//            buf1: buf1.toString(),
//            int2: int2
//        }, null, '  '));
//        return retval;
//    };

    var bClass = Java.use("java.io.OutputStream");
    bClass.write.overload('int').implementation = function(x) {
        console.log("[1] " + x);
        return this.write(x);
    }
    bClass.write.overload('[B').implementation = function(b) {
        console.log("[2] " + hex2string( bytes2hex( b ) ) );
        return this.write(b);
    }
    bClass.write.overload('[B','int','int').implementation = function(b,y,z) {
        console.log("[2] " + hex2string( bytes2hex( b ) ) + " | " + y + " | " + z);
        return this.write(b,y,z);
    }

});



Java.perform(function() {
    var Map = Java.use('java.util.Map');
    var UnityWebRequest = Java.use('com.unity3d.player.UnityWebRequest');
	console.log( Object.getOwnPropertyNames(Test.__proto__).join('\n') );

    /*
        UnityWebRequest.$init
            .overload('long', 'java.lang.String', 'java.util.Map', 'java.lang.String', 'int').implementation = function(long1, str2, map3, str4, int5) {
                console.log(this, JSON.stringify({
                    '#1': long1,
                    method: str2,
                    headers: Java.cast(map3, Map).toString(),
                    url: str4,
                    '#5': int5
                }, null, '  '));
                this.$init(long1, str2, map3, str4, int5);
            };
        Java.use('com.unity3d.player.WWW').$init.overload('int', 'java.lang.String', '[B', 'java.util.Map').implementation = function(int1, str2, bytes3, map4) {
            console.log(this, JSON.stringify({
                '#1': int1,
                str2: str2,
                bytes3: bytes3,
                map4: Java.cast(map4, Map).toString()
            }, null, '  '));
        };            
    */
    UnityWebRequest.headerCallback.overload('java.util.Map').implementation = function(map1) {
        console.log('headerCallback', Java.cast(map1, Map).toString());
        this.headerCallback(map1);
    };
    var Str = Java.use('java.lang.String');
    // var decoder = Java.use('java.nio.charset.Charset').forName("UTF-8");
    UnityWebRequest.downloadCallback.overload('java.nio.ByteBuffer', 'int').implementation = function(byteBuffer1, int2) {
        console.log('downloadCallback', JSON.stringify({
            byteBuffer1: byteBuffer1.toString(),
            int2: int2
        }, null, '  '));
//	Java.perform(function(){ console.log('--', Java.cast(byteBuffer1, Java.use('java.lang.String'))); });
        return this.downloadCallback(byteBuffer1, int2);
    };
});
/*
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        // console.log("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.indexOf("epsi") != -1) {
            console.log(
		this.lib.substr(this.lib.lastIndexOf('/') + 1, this.lib.length) + 
		' [ ' + retval + ' ] \n' + 
		Module.enumerateExportsSync(this.lib).map(function(x){return x.name}) 
            );  
        }
    }
});
*/
