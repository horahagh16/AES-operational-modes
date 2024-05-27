import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

// Generate a new AES key
fun generateKey(passphrase: String): SecretKeySpec {
    val key = MessageDigest.getInstance("SHA-256").digest(passphrase.toByteArray(Charsets.UTF_8))
    return SecretKeySpec(key, "AES")
}

// Decrypt ciphertext using the specified AES mode
fun decrypt(ciphertext: String, passphrase: String, mode: String): String {
    val key = generateKey(passphrase)
    val decoded = Base64.getDecoder().decode(ciphertext)

    return when (mode) {
        "ECB" -> decryptECB(decoded, key)
        "CBC" -> decryptCBC(decoded, key)
        "CFB" -> decryptCFB(decoded, key)
        "CTR" -> decryptCTR(decoded, key)
        "GCM" -> decryptGCM(decoded, key)
        else -> throw IllegalArgumentException("Unsupported mode: $mode")
    }
}

// Decrypt ciphertext using AES-ECB
fun decryptECB(decoded: ByteArray, key: SecretKeySpec): String {
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, key)
    val decrypted = cipher.doFinal(decoded)
    return String(decrypted)
}

// Decrypt ciphertext using AES-CBC
fun decryptCBC(decoded: ByteArray, key: SecretKeySpec): String {
    val iv = decoded.sliceArray(0 until 16)
    val encrypted = decoded.sliceArray(16 until decoded.size)
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
    val decrypted = cipher.doFinal(encrypted)
    return String(decrypted)
}

// Decrypt ciphertext using AES-CFB
fun decryptCFB(decoded: ByteArray, key: SecretKeySpec): String {
    val iv = decoded.sliceArray(0 until 16)
    val encrypted = decoded.sliceArray(16 until decoded.size)
    val cipher = Cipher.getInstance("AES/CFB/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
    val decrypted = cipher.doFinal(encrypted)
    return String(decrypted)
}


// Decrypt ciphertext using AES-CTR
fun decryptCTR(decoded: ByteArray, key: SecretKeySpec): String {
    val iv = decoded.sliceArray(0 until 16)
    val encrypted = decoded.sliceArray(16 until decoded.size)
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
    val decrypted = cipher.doFinal(encrypted)
    return String(decrypted)
}                        

// Decrypt ciphertext using AES-GCM
fun decryptGCM(decoded: ByteArray, key: SecretKeySpec): String {
    val nonceSize = 12
    val nonce = decoded.sliceArray(0 until nonceSize)
    val encrypted = decoded.sliceArray(nonceSize until decoded.size)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(128, nonce)
    cipher.init(Cipher.DECRYPT_MODE, key, spec)
    val decrypted = cipher.doFinal(encrypted)
    return String(decrypted)
}

fun main() {
    val passphrase = "my_secret_passphrase"
    val ciphertext = "3o7YNAEruh95Ro4XD4HJuI5SPZiuZW48IWdwa0lt3YREQYJeHUKRbxQ="
    val mode = "GCM" // Change this to "ECB", "CBC", "CFB", "CTR", or "GCM" as needed

    try {
        val decrypted = decrypt(ciphertext, passphrase, mode)
        println("Decrypted: $decrypted")
    } catch (e: Exception) {
        println("Error decrypting: ${e.message}")
    }
}
