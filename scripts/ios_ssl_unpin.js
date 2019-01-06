var SecTrustEvaluate_prt = Module.findExportByName("Security", "SecTrustEvaluate");
var SecTrustEvaluate = new NativeFunction(SecTrustEvaluate_prt, "int", ["pointer", "pointer"]);
Interceptor.replace(SecTrustEvaluate_prt, new NativeCallback(function(trust, result) {
  console.log("[*] SecTrustEvaluate(...) hit!");
  SecTrustEvaluate(trust, result); // call original method
  Memory.writeU8(result, 1);
  return 0;
}, "int", ["pointer", "pointer"]));
