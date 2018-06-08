/*
* By http://github.com/LotemBY *

This is a frida script for unpinning and reversing of ObjC applications.
Intercept method's which match regex.

You may change the following regex arrays to match your needs:
*/

// The list of regexs for the moudle name
var moduleKeyWords = [/.*/]; // (It is not recommended to search all the moudles)

// The list of regexs for the method name
var methodKeyWords = [/cert/i, /trust/i, /ssl/i, /verify/i, /509/]; 

// The list of regexs for the method to override their return value with "1"
var overrideKeyWords = [];

/*
To run this script with frida on iPhone, follow these steps:
	1. Make sure the iPhone is jailbreaked
	2. Download the frida server from Cydia (package: re.frida.server)
	3. Connect the iPhone to your computer with USB and open the application 
	4. Type in console "frida-ps -U" to get the list of running proccess on the iPhone, and find the proccess name of your app
	5. Type in console "frida -U <APP PROCCESS NAME> -l <PATH TO THIS SCRIPT>" to run this script
	6. Now you should use the app to trigger some of the intercepted methods
*/
var onCompleteCallback = function (retval) {};
setImmediate(function () {
	if (!ObjC.available) {
		console.log("[-] Objective-C Runtime is not available!");
		return;
	}

	console.log("=======================================================\n");
	console.log("[*] Searching methods...");

	var moduleUsed = false;

	Process.enumerateModules({
		onMatch: function(module) {

			if (!matchesRegex(moduleKeyWords, module.name)) {
				return;
			}

			moduleUsed = false;
			Module.enumerateSymbols(module.name, {
				onMatch: function(exp) {
					if (matchesRegex(methodKeyWords, exp.name)) {
						if (!moduleUsed) {
							console.log("[*] In module \"" + module.name + "\"");
							moduleUsed = true;
						}
						console.log("\t[*] Matching method: \"" + exp.name + "\", Address: " + Module.findExportByName(module.name, exp.name));

						if (intercept(module.name, exp.name)) {
							console.log("\t\t[+] Now intercepting " + exp.name);
						} else {
	    					console.log("\t\t[-] Could not intercept " + exp.name);
						}
					}
				},
				onComplete: onCompleteCallback
			});
		},
		onComplete: onCompleteCallback
	});

	console.log("[*] Completed!");
	console.log("=======================================================\n\n");
});

// Return if 'str' match any of the regexs in the array 'regexList'
function matchesRegex(regexList, str) {
	regexList.forEach(function(el) {
		if (str.search(el) != -1) 
			return true;		
	});
	return false;
}

// Try to intercept a method by moudle name and function name.
// Return 'true' on success and 'false' on failor.
function intercept(module, func) {
	try {
	    Interceptor.attach(Module.findExportByName(module, func), {
	      	onEnter: function(args) {
	      		console.log("[*] Method CALL:\t\"" + func + "\" called!");
            	},  
	        onLeave: function (retval) {
	            console.log("[*] Method RETURN:\t\"" + func + "\" (return value: " + retval + ")");

	            if (matchesRegex(overrideKeyWords, func)) {
	            	console.log("[!] CHANGED RETURN VALUE of method:\t\"" + func + "\" (new value: " + 1 + ")");
	            	retval.replace(1);
	            }
	      	}
	    });

	    return true;
	} catch (err) {
		return false;
	}
}
