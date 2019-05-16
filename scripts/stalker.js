var sendText = ObjC.classes.PhoneService['- sendText:to:withSeq:'];
Interceptor.attach(ObjC.classes.MyClass['- myMethod:param1'].implementation, {
  onEnter: function (args) {
    var tid = Process.getCurrentThreadId();
    this.tid = tid;
    Stalker.follow(tid, {
      events: {
        call: true
      },
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
