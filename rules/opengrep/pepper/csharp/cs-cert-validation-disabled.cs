using System.Net;
using System.Net.Http;
public class Tls {
  public void A() {
    // ruleid: pepper.csharp.cert-validation-disabled
    ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;
    var h = new HttpClientHandler();
    // ruleid: pepper.csharp.cert-validation-disabled
    h.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    // ok: pepper.csharp.cert-validation-disabled
    h.ServerCertificateCustomValidationCallback = (m, cert, chain, errors) => errors == System.Net.Security.SslPolicyErrors.None;
  }
}
