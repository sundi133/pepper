import java.sql.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
public class UserController extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String name = req.getParameter("name");
    Statement st = conn.createStatement();
    // ruleid: pepper.java.sql-injection
    st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    // ruleid: pepper.java.sql-injection
    PreparedStatement bad = conn.prepareStatement("SELECT * FROM t WHERE id = " + req.getParameter("id"));
    // ok: pepper.java.sql-injection
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
    ps.setString(1, name);
    // ok: pepper.java.sql-injection
    st.executeQuery("SELECT * FROM t WHERE id = " + Integer.parseInt(req.getParameter("id")));
  }
  @GetMapping("/orders")
  public List<Order> orders(@RequestParam String status, @RequestParam(defaultValue = "x") String sort) {
    // ruleid: pepper.java.sql-injection
    return em.createQuery("FROM Order o WHERE o.status = '" + status + "' ORDER BY " + sort).getResultList();
  }
  public List<Order> internal(String status) {
    // ok: pepper.java.sql-injection
    return em.createQuery("FROM Order o WHERE o.status = '" + status + "'").getResultList();
  }
}
