import frida
import sys
import subprocess

MODULE_NAME = 'libfoo.so'
FULL_METHOD_NAME = 'SomeCppClass::someMethod('
APP_NAME = 'com.app.name'

stdoutput = subprocess.getoutput('nm -DC %s | grep "%s"' % (MODULE_NAME, FULL_METHOD_NAME))
output_split = stdoutput.split()
method_address = output_split[0]
method_desc = ''.join(output_split[2:])
method_signature = method_desc[method_desc.index('(') + 1: -1].split(',')


def switch(x, i):
    return {
        'unsignedint': 'args[' + i + '].toInt32(),',
        'int': 'args[' + i + '].toInt32(),',
        'std::string': 'Memory.readUtf8String(Memory.readPointer(args[' + i + '])),',
        'bool': 'Boolean(args[' + i + ']),'
    }[x]


arguments_js = ['{']
for i in range(len(method_signature)):
    arg = method_signature[i]
    i = str(i + 1)
    arguments_js.append(i + ': ' + switch(arg, i))
arguments_js = ''.join(arguments_js) + '}'


def on_message(m, _data):
    if m['type'] == 'send':
        print(m['payload'])
    elif m['type'] == 'error':
        print(m)


js_script = """
var moduleName = "{{moduleName}}";
var nativeFuncAddr = {{methodAddress}};

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        this.lib = Memory.readUtf8String(args[0]);
        console.log("dlopen called with: " + this.lib);
    },
    onLeave: function(retval) {
        if (this.lib.endsWith(moduleName)) {
            Interceptor.attach(Module.findBaseAddress(moduleName).add(nativeFuncAddr), {
                onEnter: function(args) {
                    console.log("[+] hook invoked");
                    console.log(JSON.stringify({{arguments}}, null, '\t'));
                }
            });
        }
    }
});
"""
replaceMap = {
    '{{arguments}}': arguments_js,
    '{{methodAddress}}': '0x' + method_address,
    '{{moduleName}}': MODULE_NAME
}
for k, v in replaceMap.items():
    js_script = js_script.replace(k, v)

device = frida.get_usb_device()
pid = device.spawn([APP_NAME])
session = device.attach(pid)
script = session.create_script(js_script)
script.on('message', on_message)
script.load()
device.resume(APP_NAME)
sys.stdin.read()
