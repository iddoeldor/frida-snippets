### How to access inner class static field
```
package tech.yusi.fridademo;

public class Jingdong {
    private int intResult;

    private final static class a {
        final static Jingdong a = new Jingdong();
    }


    public Jingdong() {
        intResult = 0;
    }

    public static Jingdong a() {
        return a.a;
    }

    public static int a(int arg0, int arg1) {
        return arg0 + arg1;
    }


    public String a(String arg0, String arg1) {
        return arg0 + arg1;
    }
}
```

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida,sys

rdev = frida.get_remote_device()
session = rdev.attach("tech.yusi.fridademo")

def on_message(message ,data):
    if message['type'] == 'send':
        print(message['payload'])              
    elif message['type'] == 'error':
        print(message['stack'])
    else:
        print(message)
    
jscode = """
send(Java.available); 
Java.perform(function () {
    var JingdongA = Java.use("tech.yusi.fridademo.Jingdong$a");  
    var Jingdong = JingdongA.a;
    send(Jingdong.fieldType);
    
    var JingdongInstance = Jingdong.value;   
    var ret = JingdongInstance.a("G8", "4tar");
    send(ret);

});    
""" 

script = session.create_script(jscode)
script.on("message" , on_message)
script.load()

try:
    sys.stdin.read()
except KeyboardInterrupt as e:
    session.detach()
    sys.exit(0) 
```

