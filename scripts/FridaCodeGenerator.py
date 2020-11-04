#?shortcut=Mod1+Shift+Z
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from subprocess import Popen, PIPE


def arg_format(i):
    return 'arg_%d' % i


def generate_body_code(types, retval, method_name, orig_method_name, class_name):
    body_code = "\n\tconsole.log('[{}#{}] ' + JSON.strigify({{\n\t".format(
      FridaCodeGenerator.to_canonical_name(class_name), method_name)
    for i, typ in enumerate(types):
        body_code += '\t{}: {}, // {}\n\t'.format('a%d' % i, arg_format(i), typ)
  
    if retval != 'void':
        body_code = '\n\tvar retval = this.{}.apply(this, arguments);{}\tretv: retval\n\t}});'.format(
            orig_method_name, body_code)
    else:
        body_code += '}});\n\tthis.{}.apply(this, arguments);'.format(method_name)

    return body_code + '\n'


class JavaMethod(object):
    def __init__(self):
        self.class_name = None
        self.class_orig_name = None
        self.name = None
        self.orig_name = None
        self.arg = []
        self.retType = None

    def get_parameters(self):
        return self.arg

    def get_return_type(self):
        return self.retType

    def get_name(self):
        return self.name

    def get_orig_name(self):
        return self.orig_name

    def get_class_orig_name(self):
        return self.class_orig_name

    def get_class_name(self):
        return self.class_name

    def __str__(self):
        return 'JavaMethod[name: %s, orig_name: %s, args: %s, return type: %s]' % (
            self.name, self.orig_name, self.arg, self.retType)


class FridaCodeGenerator(IScript):

    @staticmethod
    def to_canonical_name(mname):
        mname = mname.replace('/', '.')
        return {
            'C': 'char',
            'I': 'int',
            'B': 'byte',
            'Z': 'boolean',
            'F': 'float',
            'D': 'double',
            'S': 'short',
            'J': 'long',
            'V': 'void',
            'L': mname[1:-1],
            '[': mname
        }[mname[0]]

    def run(self, ctx):
        project = ctx.getEnginesContext().getProjects()[0]  # Get current project(IRuntimeProject)
        self.dexunit = RuntimeProjectUtil.findUnitsByType(project, IDexUnit, False)[0]  # Get dex context, needs >=V2.2.1
        try:
            self.current_unit = ctx.getFocusedView().getActiveFragment().getUnit()  # Get current Source Tab in Focus
            java_class = self.current_unit.getClassElement().getName()
            current_addr = ctx.getFocusedView().getActiveFragment().getActiveAddress()
            m = FridaCodeGenerator.get_decompiled_method(self.dexunit, current_addr, java_class)
            method_name = m.get_name()
            class_name = FridaCodeGenerator.to_canonical_name(m.get_class_orig_name())
            return_type = FridaCodeGenerator.to_canonical_name(str(m.get_return_type()))
            if method_name == '<clinit>':
                raise Exception('Class initializer')
            args_code = ', '.join([arg_format(i) for i in range(len(m.get_parameters()))])

            if method_name == '<init>': method_name = '$init'

            types = [FridaCodeGenerator.to_canonical_name(param) for param in m.get_parameters()]
            # TODO get original type class names
            type_code = ', '.join(["'{0}'".format(t) for t in types])
            body_code = generate_body_code(types, return_type, method_name, m.get_orig_name(), m.get_class_name())
            hook = "Java.use('{class_name}').{method}.overload({sig}).implementation = function({args}) {{{body}}}".format(
                class_name=class_name, 
                method=m.get_orig_name() if method_name != '$init' else method_name, 
                sig=type_code, 
                args=args_code, 
                body=body_code
            )
            print(hook)
            # copy to system's clipboard
            Popen(['xclip', '-sel', 'c', '-i'], stdin=PIPE).communicate(input=(hook.encode()))
        except Exception as e:
            print(e)
            ctx.displayMessageBox(None, 'Place the cursor in the function you want to generate the Frida code', None, None)

    @staticmethod
    def get_decompiled_method(dex, addr, class_orig_name):
        method_info = JavaMethod()
        method_info.orig_name = dex.getMethod(addr).getName(False)
        msig = addr.split('+')[0]
        infos = str(msig).split('->')
        if len(infos) == 2:
            method_info.class_name = infos[0]
            method_info.class_orig_name = class_orig_name
            if len(infos[1].split('(')) == 2:
                method_info.name = infos[1].split('(')[0]
            if len(infos[1].split(')')) == 2:
                method_info.retType = infos[1].split(')')[1]
            if len(infos[1].split('(')) == 2 and len(infos[1].split(')')) == 2:
                args = infos[1].split('(')[-1].split(')')[0]
                while args:
                    if args[0] in ['C', 'I', 'B', 'Z', 'F', 'D', 'S', 'J', 'V']:
                        method_info.arg.append(str(args[0]))
                        args = args[1:]
                    elif args[0] == '[':
                        if args[1] == 'L':
                            offset = args.find(';')
                            method_info.arg.append(str(args[0:offset + 1]))
                            args = args[offset + 1:]
                        else:
                            method_info.arg.append(str(args[0:2]))
                            args = args[2:]
                    elif args[0] == 'L':
                        offset = args.find(";")
                        method_info.arg.append(str(args[0:offset + 1]))
                        args = args[offset + 1:]
                print(method_info)
        return method_info
