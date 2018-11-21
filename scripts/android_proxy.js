// open proxy (not working)
Java.perform(function() {
    Java.use('android.net.Proxy').setHttpProxySystemProperty(Java.use('android.net.ProxyInfo').buildDirectProxy('1.0.0.1', 8081));
});
