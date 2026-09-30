// License: GNU Lesser General Public License v3.0
// source (original): https://github.com/mobsf/mobsfscan/blob/main/tests/assets/rules/semgrep/webview/webview_debugging.java
// hash: e29e85c3

package com.myapp;

import com.facebook.react.ReactActivity;
import android.webkit.WebView;

public class MainActivity extends ReactActivity {

    /**
     * Returns the name of the main component registered from JavaScript.
     * This is used to schedule rendering of the component.
     */
    @Override
    protected String getMainComponentName() {
        return "myapp";
    }

    @Override
    protected void onCreate() {
        super.onCreate();
        //added this line with necessary imports at the top.
        // ruleid:rules_lgpl_java_webview_rule-webview-debugging
        WebView.setWebContentsDebuggingEnabled(true);
    }
}