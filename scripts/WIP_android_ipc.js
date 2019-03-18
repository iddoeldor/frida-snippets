var ContextWrapper = Java.use("android.content.ContextWrapper");

ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
  send(JSON.stringify({
    _intent: intent.toString(),
    extras: intent.getExtras() ? intent.getExtras().toString() : 'null',
    flags: intent.getFlags().toString()
  }));
  return this.sendBroadcast.overload("android.content.Intent").apply(this, arguments);
}

ContextWrapper.sendBroadcast.overload("android.content.Intent", "java.lang.String").implementation = function(intent, receiverPermission) {
  send(JSON.stringify({
    
  });
  return this.sendBroadcast.overload("android.content.Intent", "java.lang.String").apply(this, arguments);
}


ContextWrapper.sendStickyBroadcast.overload("android.content.Intent").implementation = function(intent) {

  return this.sendStickyBroadcast.overload("android.content.Intent").apply(this, arguments);
}

ContextWrapper.startActivity.overload("android.content.Intent").implementation = function(intent) {
  
  return this.startActivity.overload("android.content.Intent").apply(this, arguments);
}
