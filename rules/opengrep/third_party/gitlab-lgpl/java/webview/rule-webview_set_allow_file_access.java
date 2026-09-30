// License: GNU Lesser General Public License v3.0
// source (original): https://github.com/mobsf/mobsfscan/blob/main/tests/assets/rules/semgrep/webview/webview_file_access.java
// hash: e29e85c3

class Webview extends WebViewClient {
        public void vulnerableMethodSetAllowFileAccess() {
                WebView web = (WebView) findViewById(R.id.webview);
        }
        public void vulnerableMethodSetAllowFileAccess2() {
                WebView web = (WebView) findViewById(R.id.webview);
                WebSettings webSettings = web.getSettings();
                webSettings.setWebContentsDebuggingEnabled(true);
                // ruleid:rules_lgpl_java_webview_rule-webview-set-allow-file-access
                webSettings.setAllowFileAccess(true);
        }

         public void vulnerableMethodSetAllowFileAccess1() {
                boolean fileAccess = true;
                WebView web = (WebView) findViewById(R.id.webview);
                WebSettings webSettings = web.getSettings();
                webSettings.setWebContentsDebuggingEnabled(true);
                // ruleid:rules_lgpl_java_webview_rule-webview-set-allow-file-access
                webSettings.setAllowFileAccess(fileAccess);
        }

          public void vulnerableMethodSetAllowFileAccessok() {
                boolean fileAccess = false;
                WebView web = (WebView) findViewById(R.id.webview);
                WebSettings webSettings = web.getSettings();
                webSettings.setWebContentsDebuggingEnabled(true);
                // ok:rules_lgpl_java_webview_rule-webview-set-allow-file-access
                webSettings.setAllowFileAccess(fileAccess);
        }
}
