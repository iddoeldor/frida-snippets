import frida
import sys
import subprocess

MODULE_NAME = 'libfoo.so'
FULL_METHOD_NAME = 'SomeCppClass::someMethod('
APP_NAME = 'com.app.name'


def on_message(m, _data):
    if m['type'] == 'send':
        print(m['payload'])
    elif m['type'] == 'error':
        print(m)


def switch(argument_key, idx):
    argument_key = argument_key.replace(' ', '')
    return '%d: %s' % (idx, {
        'unsignedint': 'args[%d].toInt32(),',
        'int': 'args[%d].toInt32(),',
        'std::string': 'Memory.readUtf8String(Memory.readPointer(args[%d])),',
        'bool': 'Boolean(args[%d]),'
    }[argument_key] % idx)


js_script = """
var moduleName = "{{moduleName}}",
    nativeFuncAddr = {{methodAddress}};

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
output = subprocess.getoutput('nm --demangle --dynamic %s | grep "%s"' % (MODULE_NAME, FULL_METHOD_NAME))
print('[+] nm output:', output)
# extract the arguments which are inside parenthesis in `nm -DC` stdout
method_args = re.search(r'\((.*?)\)', output).group(1).split(',')
print('[+] Method arguments:', method_args)
for k, v in {
    '{{moduleName}}': MODULE_NAME,
    '{{methodAddress}}': '0x' + output.split()[0],
    '{{arguments}}': '{' + ''.join([switch(method_args[i], i + 1) for i in range(len(method_args))]) + '}'
}.items():
    js_script = js_script.replace(k, v)
print('[+] JS Script:\n', js_script)

device = frida.get_usb_device()
pid = device.spawn([APP_NAME])
session = device.attach(pid)
script = session.create_script(js_script)
script.on('message', on_message)
script.load()
device.resume(APP_NAME)
sys.stdin.read()

# TODO if no arguments > print no arguments
# TODO handle other arguments, [long, longlong..]
