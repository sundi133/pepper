import javax.net.ssl.*;
import java.security.cert.X509Certificate;
public class Tls {
  TrustManager tm = new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] c, String a) {}
    // ruleid: pepper.java.tls-trust-all
    public void checkServerTrusted(X509Certificate[] c, String a) {}
    public X509Certificate[] getAcceptedIssuers() { return null; }
  };
  void a() {
    // ruleid: pepper.java.tls-trust-all
    HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
  }
  TrustManager ok = new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] c, String a) {}
    // ok: pepper.java.tls-trust-all
    public void checkServerTrusted(X509Certificate[] c, String a) throws java.security.cert.CertificateException { delegate.checkServerTrusted(c, a); }
    public X509Certificate[] getAcceptedIssuers() { return null; }
  };
}
