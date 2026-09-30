import org.springframework.web.bind.annotation.*
@RestController
class Ops {
    @PostMapping("/ping")
    fun ping(@RequestParam host: String) {
        // ruleid: pepper.kotlin.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host)
        // ruleid: pepper.kotlin.command-injection
        ProcessBuilder("sh", "-c", "nslookup $host").start()
        // ok: pepper.kotlin.command-injection
        ProcessBuilder("uptime").start()
    }
}
