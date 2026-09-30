using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class ToolsController : ControllerBase {
  public IActionResult Ping(string host) {
    // ruleid: pepper.csharp.command-injection
    Process.Start("cmd.exe", "/c ping " + host);
    var psi = new ProcessStartInfo("ping");
    // ruleid: pepper.csharp.command-injection
    psi.Arguments = "-n 1 " + host;
    // ok: pepper.csharp.command-injection
    Process.Start("notepad.exe");
    return Ok();
  }
}
