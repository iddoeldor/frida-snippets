def on_message(m, _data):
    if m['type'] == 'send':
        print(m['payload'])
    elif m['type'] == 'error':
        print(m)


def switch(argument_key, idx):
    """
    c/c++ variable type to javascript reader switch implementation
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


def list_symbols_from_object_files(module_id):
    import subprocess
    return subprocess.getoutput('nm --demangle --dynamic %s' % module_id)


def parse_nm_output(nm_stdout, symbols):
    for line in nm_stdout.splitlines():
        split = line.split()
        open_parenthesis_idx = line.find('(')
        raw_arguments = [] if open_parenthesis_idx == -1 else line[open_parenthesis_idx + 1:-1]
        if len(raw_arguments) > 0:  # ignore methods without arguments
            raw_argument_list = raw_arguments.split(',')
            symbols.append({
                'address': split[0],
                'type': split[1],  # @see Symbol Type Table
                'name': split[2][:split[2].find('(')],  # method name
                'args': raw_argument_list
            })


def get_js_script(method, module_id):
    js_script = """
        var moduleName = "{{moduleName}}", nativeFuncAddr = {{methodAddress}};
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
    return js_script


def main(app_id, module_id, method):
    """
    $ python3.x+ script.py --method SomeClass::someMethod --app com.company.app --module libfoo.so
    :param app_id: application identifier / bundle id 
    :param module_id: shared object identifier / known suffix, will iterate loaded modules (@see dlopen) 
    :param method: method/symbol name
    :return: hook native method and print arguments when invoked
    """
    # TODO extract all app's modules via `adb shell -c 'ls -lR /data/app/' + app_if + '*' | grep "\.so"`

    nm_stdout = list_symbols_from_object_files(module_id)

    symbols = []
    parse_nm_output(nm_stdout, symbols)

    selection_idx = None
    for idx, symbol in enumerate(symbols):
        if method is None:  # if --method flag is not passed
            print("%4d) %s (%d)" % (idx, symbol['name'], len(symbol['args'])))
        elif method == symbol['name']:
            selection_idx = idx
            break
    if selection_idx is None:
        if method is None:
            selection_idx = input("Enter symbol number: ")
        else:
            print('[+] Method not found, remove method flag to get list of methods to select from, `nm` stdout:')
            print(nm_stdout)
            exit(2)

    method = symbols[int(selection_idx)]
    print('[+] Selected method: %s' % method['name'])
    print('[+] Method arguments: %s' % method['args'])

    from frida import get_usb_device
    device = get_usb_device()
    pid = device.spawn([app_id])
    session = device.attach(pid)
    script = session.create_script(get_js_script(method, module_id))
    script.on('message', on_message)
    script.load()
    device.resume(app_id)
    # keep hook alive
    from sys import stdin
    stdin.read()


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('--app', help='app identifier "com.company.app"')
    parser.add_argument('--module', help='loaded module name "libfoo.2.so"')
    parser.add_argument('--method', help='method name "SomeClass::someMethod", if empty it will print select-list')
    args = parser.parse_args()
    main(args.app, args.module, args.method)


"""
Symbol Type Table:
    "A" The symbol's value is absolute, and will not be changed by further linking.
    "B" The symbol is in the uninitialized data section (known as BSS).
    "C" The symbol is common.  Common symbols are uninitialized data.
       When linking, multiple common symbols may appear	with the same name.  
       If the symbol is defined anywhere, the common symbols are treated as undefined	references.
    "D" The symbol is in the initialized data section.
    "G" The symbol is in an initialized data section for small objects.
       Some object file formats permit more efficient access to small data objects, such as a global int variable as 
       opposed to a large global array.
    "I" The symbol is an indirect reference to another symbol.
       This is a GNU extension to the a.out object file format which is rarely used.
    "N" The symbol is a debugging symbol.
    "R" The symbol is in a read only data section.
    "S" The symbol is in an uninitialized data section for small objects.
    "T" The symbol is in the text (code) section.
    "U" The symbol is undefined.
    "V" The symbol is a weak object. When a weak defined symbol is linked with a normal defined symbol, 
        the normal defined symbol is used with no error.  
        When a weak undefined symbol is linked and the symbol is not defined, the value of the weak symbol becomes 
        zero with no error.
    "W" The symbol is a weak symbol that has not been specifically tagged as a weak object symbol. 
        When a weak defined symbol is linked with a normal defined symbol, 
        the normal defined symbol is used with no error.  
        When a weak undefined symbol is linked and the symbol is not defined, the value of the symbol is determined 
        in a system-specific manner without error.  
        On some systems, uppercase indicates that a default value has been specified.
    "-" The symbol is a stabs symbol in an a.out object file.  
        In this case, the next values printed are the stabs other field, the stabs desc field, and the stab type.  
        Stabs symbols are used to hold debugging information.
    "?" The symbol type is unknown, or object file format specific.
"""
