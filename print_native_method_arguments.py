import sys
import frida
import subprocess

APP_NAME = 'com.app.sample'
MODULE_NAME = 'libfoo.so'


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
        'bool': 'Boolean(args[%d]),'  # TODO handle other arguments, [long, longlong..]
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
output = subprocess.getoutput('nm --demangle --dynamic %s' % MODULE_NAME)

symbols = []
for line in output.splitlines():
    try:
        split = line.split()
        raw_arguments = line[line.index('(') + 1:-1]
        argument_list = [] if len(raw_arguments) is 0 else raw_arguments.split(',')
        symbols.append({
            'address': split[0],
            'type': split[1],
            'name': split[2][:split[2].index('(')],
            'args': argument_list
        })
    except ValueError:
        pass

for idx, symbol in enumerate(symbols):
    print("{}) {} ".format(idx, symbol['name'] + ' ' + str(len(symbol['args']))))
selection_idx = input("Enter symbol number: ")
method = symbols[int(selection_idx)]
print('[+] Selected method: %s' % method['name'])
print('[+] Method arguments: %s' % method['args'])

for k, v in {
    '{{moduleName}}': MODULE_NAME,
    '{{methodAddress}}': '0x' + method['address'],
    '{{arguments}}': '{' + ''.join([switch(method['args'][i], i + 1) for i in range(len(method['args']))]) + '}'
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

"""
Symbol Type:
    "A" The symbol's value is absolute, and will	not be changed by further linking.
    "B" The symbol is in the uninitialized data section (known as BSS).
    "C" The symbol is common.  Common symbols are uninitialized data.
       When linking, multiple common symbols may appear	with the same
       name.  If the symbol is defined anywhere, the common symbols
       are treated as undefined	references.
    "D" The symbol is in the initialized data section.
    "G" The symbol is in an initialized data section for small objects.
       Some object file formats permit more efficient access to small
       data objects, such as a global int variable as opposed to a
       large global array.
    "I" The symbol is an indirect reference to another symbol.
       This is a GNU extension to the a.out object file format which is rarely used.
    "N" The symbol is a debugging symbol.
    "R" The symbol is in a read only data section.
    "S" The symbol is in an uninitialized data section for small objects.
    "T" The symbol is in the text (code) section.
    "U" The symbol is undefined.
    "V" The symbol is a weak object. When a weak defined symbol is
       linked with a normal defined symbol, the normal defined symbol
       is used with no error.  When a weak undefined symbol is linked
       and the symbol is not defined, the value of the weak symbol
       becomes zero with no error.
    "W" The symbol is a weak symbol that has not been specifically
       tagged as a weak object symbol. When a weak defined symbol is
       linked with a normal defined symbol, the normal defined symbol
       is used with no error.  When a weak undefined symbol is linked
       and the symbol is not defined, the value of the symbol is
       determined in a system-specific manner without error.  On some
       systems, uppercase indicates that a default value has been
       specified.
    "-" The symbol is a stabs symbol in an a.out object file.  In this
       case, the next values printed are the stabs other field, the
       stabs desc field, and the stab type.  Stabs symbols are used to
       hold debugging information.
    "?" The symbol type is unknown, or object file format specific.
"""
