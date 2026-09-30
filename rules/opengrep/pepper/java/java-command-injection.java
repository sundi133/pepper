import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
public class Ops {
  public void ping(HttpServletRequest req) throws Exception {
    // ruleid: pepper.java.command-injection
    Runtime.getRuntime().exec("ping -c 1 " + req.getParameter("host"));
    // ok: pepper.java.command-injection
    Runtime.getRuntime().exec(new String[] {"uptime"});
  }
  @PostMapping("/convert")
  public void convert(@RequestParam("file") String file) throws Exception {
    // ruleid: pepper.java.command-injection
    new ProcessBuilder("sh", "-c", "convert " + file + " out.png").start();
  }
}
