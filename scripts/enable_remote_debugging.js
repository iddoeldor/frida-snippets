/*
Enable remote debugging of Android WebViews at Runtime using Frida
run "adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'" to get the current activity
*/
Java.perform(function() {
  Java.deoptimizeEverything();
  var injected = false;
  Java.choose('com.app.SomeActivity', {
    'onMatch': function(o) {
      var Runnable = Java.use('java.lang.Runnable');
      var MyRunnable = Java.registerClass({
        name: 'com.example.MyRunnable',
        implements: [Runnable],
        methods: {
          'run': function() {
            Java.use('android.webkit.WebView').setWebContentsDebuggingEnabled(true);
          }
        }
      }); 
      var runnable = MyRunnable.$new();
      o.runOnUiThread(runnable);
      console.log('\nWebview debug enabled......');
      
    },
    'onComplete': function() {
      console.log('completed');
    }
  })
});
