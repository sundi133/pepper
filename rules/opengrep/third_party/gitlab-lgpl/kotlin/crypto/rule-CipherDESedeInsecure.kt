// License: LGPL-3.0 License (c) find-sec-bugs
package crypto

import java.security.Provider
import javax.crypto.Cipher

/** Use for test the identification of DES ciphers, AES/ECB. */
@Suppress("DEPRECATION")
object BlockCipherList {
    @Throws(Exception::class)
    @JvmStatic
    fun main(args: Array<String>) {
        // Note : Not a realistic code sample (no encryption occurs)

        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("AES/CBC/NoPadding")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("AES/ECB/NoPadding", "IBMJCE")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("AES/ECB/PKCS5Padding", ExampleProvider())
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DES/CBC/NoPadding", ExampleProvider())
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DES/CBC/PKCS5Padding")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DES/ECB/NoPadding")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DES/ECB/PKCS5Padding")
        // ruleid: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DESede")
        // ruleid: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DESede/CBC/NoPadding")
        // ruleid: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DESede/CBC/PKCS5Padding")
        // ruleid: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DESede/ECB/NoPadding")
        // ruleid: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DESede/ECB/PKCS5Padding")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("RSA/ECB/PKCS1Padding")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("RC2/ECB/PKCS5Padding")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("ARCFOUR/ECB/NOPADDING")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DES/CBC/NoPadding", "SunJCE")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("DES")
        // ok: kotlin_crypto_rule-CipherDESedeInsecure
        Cipher.getInstance("RSA") // Just to test a cipher with a different format in the input
    }

    /** Sun provider are at risk to be remove. This example provider will be easier to maintain. */
    internal class ExampleProvider : Provider("exampl", 1.0, "")
}
