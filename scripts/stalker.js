Interceptor.attach(ObjC.classes.MyClass['- myMethod:param1'].implementation, {
  onEnter: function (args) {
    console.warn(JSON.stringify({
      fname: args[1].readCString(),
      text: new ObjC.Object(args[2]).toString(),
      backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(m => m.moduleName+'!'+m.name),
      ctx: this.context
    }, null, 2));    
    var tid = Process.getCurrentThreadId();
    this.tid = tid;
    Stalker.follow(tid, {
      events: {
        call: true
      },
      /*
      onCallSummary: function (summary) {
        Object.keys(summary).forEach(s => {
          var sym = DebugSymbol.fromAddress(ptr(s));
          if (sym.moduleName == 'Viber')
            console.log(summary[s], sym.name);
        })
      }
      */
      transform: function (iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
          iterator.keep();
          if (instruction.mnemonic.startsWith('bl')) {
            try {
              console.log('#' + tid + ':' + DebugSymbol.fromAddress(ptr(instruction.operands[0].value)));
            } catch (e) {
              // ignoring branch&link to register 
            }
          }
        }
      }
    });
  },
  onLeave: function (retval) {
    Stalker.unfollow(this.tid);
    Stalker.garbageCollect();
  }
})
