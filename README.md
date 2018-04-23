### learn-frida-the-hard-way

TODOs: Add GIFs & docs


* Constructor override

        Java.use('java.lang.StringBuilder').$init.overload('java.lang.String').implementation = function(stringArgument) {
            console.log("c'tor");
            return this(stringArgument);
        };

