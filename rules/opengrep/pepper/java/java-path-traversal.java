import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;
public class Files1 {
  public void get(HttpServletRequest req) throws Exception {
    String f = req.getParameter("f");
    // ruleid: pepper.java.path-traversal
    new File("/data/" + f).delete();
    // ruleid: pepper.java.path-traversal
    InputStream in = new FileInputStream("/srv/files/" + req.getParameter("name"));
    // ok: pepper.java.path-traversal
    new File("/data/", FilenameUtils.getName(f)).delete();
    // ok: pepper.java.path-traversal
    new File("/data/static.txt").delete();
  }
}
