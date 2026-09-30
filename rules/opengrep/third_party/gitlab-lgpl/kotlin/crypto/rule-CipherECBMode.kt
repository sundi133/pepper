// License: LGPL-3.0 License (c) find-sec-bugs
@file:Suppress("DEPRECATION")

package crypto

import java.security.Provider
import javax.crypto.Cipher

/** Use for test the identification of DES ciphers, AES/ECB. */
object ECBMode {
    @Throws(Exception::class)
    @JvmStatic
    fun main(args: Array<String>) {
        // Note : Not a realistic code sample (no encryption occurs)

        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("AES/CBC/NoPadding")
        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("AES/ECB/NoPadding", "IBMJCE")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("AES/ECB/PKCS5Padding", ExampleProvider())
        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DES/CBC/NoPadding", ExampleProvider())
        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DES/CBC/PKCS5Padding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DES/ECB/NoPadding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DES/ECB/PKCS5Padding")
        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DESede/CBC/NoPadding")
        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DESede/CBC/PKCS5Padding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DESede/ECB/NoPadding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DESede/ECB/PKCS5Padding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("RSA/ECB/PKCS1Padding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("RC2/ECB/PKCS5Padding")
        // ruleid: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("ARCFOUR/ECB/NOPADDING")
        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DES/CBC/NoPadding", "SunJCE")
        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("DES")
        // ok: kotlin_crypto_rule-CipherECBMode
        Cipher.getInstance("RSA") // Just to test a cipher with a different format in the input
    }

    /** Sun provider are at risk to be remove. This example provider will be easier to maintain. */
    internal class ExampleProvider : Provider("example", 1.0, "")
}
