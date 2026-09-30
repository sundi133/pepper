using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
public class AccountController : Controller {
  public IActionResult Find(string name, int page) {
    // ruleid: pepper.csharp.sql-injection
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
    // ruleid: pepper.csharp.sql-injection
    var rows = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'").ToList();
    // ok: pepper.csharp.sql-injection
    var safe = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
    safe.Parameters.AddWithValue("@name", name);
    // ok: pepper.csharp.sql-injection
    var interp = db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}").ToList();
    // ok: pepper.csharp.sql-injection
    var paged = new SqlCommand("SELECT TOP 10 * FROM Users OFFSET " + page, conn);
    return Ok();
  }
}
public class ReportService {
  public void Run(string name) {
    // ok: pepper.csharp.sql-injection
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
  }
}
