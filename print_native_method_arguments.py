def on_message(m, _data):
    if m['type'] == 'send':
        print(m['payload'])
    elif m['type'] == 'error':
        print(m)


def switch(argument_key, idx):
    """
    # TODO handle other arguments, [long, longlong..]
    :param argument_key: variable type
    :param idx: index in symbols array
    :return: javascript to read the type of variable
    """
    argument_key = argument_key.replace(' ', '')
    return '%d: %s' % (idx, {
        'int': 'args[%d].toInt32(),',
        'unsignedint': 'args[%d].toInt32(),',
        'std::string': 'Memory.readUtf8String(Memory.readPointer(args[%d])),',
        'bool': 'Boolean(args[%d]),'
    }[argument_key] % idx)


def main(app_id, module_id, method):
    import subprocess
    output = subprocess.getoutput('nm --demangle --dynamic %s' % module_id)

    symbols = []
    for line in output.splitlines():
        try:
            split = line.split()
            raw_arguments = line[line.index('(') + 1:-1]
            argument_list = [] if len(raw_arguments) is 0 else raw_arguments.split(',')
            if len(argument_list) > 0:  # ignore methods without arguments
                symbols.append({
                    'address': split[0],
                    'type': split[1],  # @see Symbol Type Table
                    'name': split[2][:split[2].index('(')],  # method name
                    'args': argument_list
                })
        except ValueError:
            pass

    selection_idx = None

    for idx, symbol in enumerate(symbols):
        if method is None:
            print("%4d) %s (%d)" % (idx, symbol['name'], len(symbol['args'])))
        elif method == symbol['name']:
            selection_idx = idx
            break

    if selection_idx is None:
        selection_idx = input("Enter symbol number: ")

    method = symbols[int(selection_idx)]
    print('[+] Selected method: %s' % method['name'])
    print('[+] Method arguments: %s' % method['args'])

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
    replace_map = {
        '{{moduleName}}': module_id,
        '{{methodAddress}}': '0x' + method['address'],
        '{{arguments}}': '{' + ''.join([switch(method['args'][i], i + 1) for i in range(len(method['args']))]) + '}'
    }
    for k, v in replace_map.items():
        js_script = js_script.replace(k, v)
    print('[+] JS Script:\n', js_script)

    import frida
    device = frida.get_usb_device()
    pid = device.spawn([app_id])
    session = device.attach(pid)
    script = session.create_script(js_script)
    script.on('message', on_message)
    script.load()
    device.resume(app_id)

    import sys
    sys.stdin.read()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', help='app identifier "com.company.app"')
    parser.add_argument('--module', help='loaded module name "libfoo.2.so"')
    parser.add_argument('--method', help='method name "SomeClass::someMethod", if empty it will print select-list')
    args = parser.parse_args()
    main(args.app, args.module, args.method)


"""
Symbol Type Table:
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
