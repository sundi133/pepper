import org.springframework.web.bind.annotation.*
@RestController
class UserApi(val jdbc: JdbcTemplate) {
    @GetMapping("/users")
    fun find(@RequestParam name: String, @RequestParam("page") page: String): Any {
        // ruleid: pepper.kotlin.sql-injection
        return jdbc.queryForList("SELECT * FROM users WHERE name = '$name'")
    }
    @GetMapping("/users2")
    fun find2(@RequestParam name: String): Any {
        // ok: pepper.kotlin.sql-injection
        return jdbc.queryForList("SELECT * FROM users WHERE name = ?", name)
    }
    fun internal(name: String): Any {
        // ok: pepper.kotlin.sql-injection
        return jdbc.queryForList("SELECT * FROM users WHERE name = '$name'")
    }
}
