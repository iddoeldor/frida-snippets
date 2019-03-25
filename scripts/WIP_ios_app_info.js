function dictFromNSDictionary(nsDict) {
  var jsDict = {};
  var keys = nsDict.allKeys();
  var count = keys.count();
  for (var i = 0; i < count; i++) {
    var key = keys.objectAtIndex_(i);
    var value = nsDict.objectForKey_(key);
    jsDict[key.toString()] = value.toString();
  }
  return jsDict;
}

function arrayFromNSArray(nsArray) {
  var jsArray = [];
  var count = nsArray.count();
  for (var i = 0; i < count; i++) {
    jsArray[i] = nsArray.objectAtIndex_(i).toString();
  }
  return jsArray;
}

function infoDictionary() {
  if (ObjC.available && "NSBundle" in ObjC.classes) {
    var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
    return dictFromNSDictionary(info);
  }
  return null;
}

function infoLookup(key) {
  if (ObjC.available && "NSBundle" in ObjC.classes) {
    var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
    var value = info.objectForKey_(key);
    if (value === null) {
      return value;
    } else if (value.class().toString() === "__NSCFArray") {
      return arrayFromNSArray(value);
    } else if (value.class().toString() === "__NSCFDictionary") {
      return dictFromNSDictionary(value);
    } else {
      return value.toString();
    }
  }
  return null;
}

console.warn(JSON.stringify({
  name: infoLookup("CFBundleName"),
  bundleId: ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString(),
  version: infoLookup("CFBundleVersion"),
  path: {
    bundle: ObjC.classes.NSBundle.mainBundle().bundlePath().toString(),
    data: ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString(),
    binary: ObjC.classes.NSBundle.mainBundle().executablePath().toString()
  },
  info: infoDictionary()
}, null, 2))
