using Microsoft.AspNetCore.Mvc;
public class AuthController : Controller {
  public IActionResult Login(string returnUrl) {
    // ruleid: pepper.csharp.open-redirect
    return Redirect(returnUrl);
  }
  public IActionResult Login2(string returnUrl) {
    if (Url.IsLocalUrl(returnUrl)) {
      // ok: pepper.csharp.open-redirect
      return Redirect(returnUrl);
    }
    return RedirectToAction("Index");
  }
}
