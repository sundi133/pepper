// License: LGPL-3.0 License (c) find-sec-bugs
package crypto

import javax.crypto.Cipher

class CipherNoIntegrity {
    private var cipher: Cipher? = null
    fun x() {
        // ruleid: kotlin_crypto_rule-CipherIntegrity
        cipher = Cipher.getInstance("AES/CTR/NoPadding")
    }

    companion object {
        fun main(args: Array<String>) {
            // ok: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("AES/GCM/...") // ok
            // ruleid: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("AES") // ECB and no integrity
            // ruleid: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("DES/CTR/NoPadding", "BC") // no integrity
            // ruleid: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("DESede/ECB/PKCS5Padding") // ECB and no integrity
            // ruleid: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("AES/CBC/PKCS5Padding") // oracle and no integrity
            // ok: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("RSA") // ok
            // ok: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("RSA/ECB/PKCS1Padding") // ok
            // ok: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance(args[0]) // ok
            // ok: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("ECIES") // ok this is elliptic curve
            // ok: kotlin_crypto_rule-CipherIntegrity
            Cipher.getInstance("AES/GCM-SIV/NoPadding") // ok
        }
    }
}