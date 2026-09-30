// License: GNU Lesser General Public License v3.0
// source (original): https://github.com/mobsf/mobsfscan/blob/main/tests/assets/rules/semgrep/webview/webview_external_storage.java
// hash: e29e85c3

// ruleid:rules_lgpl_java_webview_rule-webview-external-storage
String path = Environment.getExternalStorageDirectory().toString() + "/Download/income_tax_return.pdf";
mWebView.loadUrl( "file:///android_asset/pdfjs/web/viewer.html?file=" + path);
mWebView.loadUrl(path);

mWebView.loadUrl( path + "file:///android_asset/pdfjs/web/viewer.html?file=");


mWebView.loadUrl(Environment.getExternalStorageDirectory() + "/doo");


// ruleid:rules_lgpl_java_webview_rule-webview-external-storage
engine.loadUrl("file:///" + Environment.getExternalStorageDirectory().getPath() + "testing.html");


// ruleid:rules_lgpl_java_webview_rule-webview-external-storage
engine.loadUrl("file:///"+Environment.getExternalStorageDirectory().getAbsolutePath() + "testing.html");