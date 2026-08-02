# Keep the JS bridge surface intact for @JavascriptInterface reflection.
-keepclassmembers class com.ant.emichaosbg.EmiBridge {
    @android.webkit.JavascriptInterface <methods>;
}
