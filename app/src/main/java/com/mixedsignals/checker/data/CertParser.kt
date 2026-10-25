package com.mixedsignals.checker.data

import com.mixedsignals.checker.domain.model.CertInfo
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.security.auth.x500.X500Principal

/** Chuyển chứng chỉ X.509 (DER) thành [CertInfo]. Chỉ dùng Java SE nên chạy được cả trên JVM test. */
object CertParser {
    private val OID_NAMES = mapOf(
        "1.2.840.113549.1.9.1" to "EMAILADDRESS",
        "2.5.4.5" to "SERIALNUMBER",
        "2.5.4.12" to "T",
        "2.5.4.42" to "GIVENNAME",
        "2.5.4.4" to "SURNAME",
    )

    fun parse(der: ByteArray): CertInfo? = try {
        val cf = CertificateFactory.getInstance("X.509")
        val c = cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        fromX509(c)
    } catch (e: Exception) {
        null
    }

    fun fromX509(c: X509Certificate): CertInfo {
        val subject = parseDn(c.subjectX500Principal)
        val issuer = parseDn(c.issuerX500Principal)
        // Như paper §3: chứng chỉ tự ký có subject trùng issuer. Không dựa vào verify() vì các
        // chứng chỉ cũ (MD5withRSA...) có thể không kiểm được chữ ký trên máy mới.
        val selfSigned = c.subjectX500Principal == c.issuerX500Principal
        val key = c.publicKey
        val bits = when (key) {
            is RSAPublicKey -> key.modulus.bitLength()
            is ECPublicKey -> key.params.curve.field.fieldSize
            is DSAPublicKey -> key.params?.p?.bitLength()
            else -> null
        }
        return CertInfo(
            sha256 = sha256Hex(c.encoded),
            subject = subject,
            issuer = issuer,
            selfSigned = selfSigned,
            notBefore = c.notBefore.time,
            notAfter = c.notAfter.time,
            sigAlg = c.sigAlgName,
            keyAlg = key.algorithm,
            keySizeBits = bits,
        )
    }

    fun parseDn(p: X500Principal): Map<String, String> = parseRfc2253(p.getName(X500Principal.RFC2253, OID_NAMES))

    /**
     * Tách chuỗi DN dạng RFC 2253 ("CN=a\,b,O=c") thành map. Xử lý ký tự thoát, giá trị trong ngoặc kép
     * và giá trị hex "#..." (chuỗi DER). Giá trị rỗng bị bỏ.
     */
    fun parseRfc2253(dn: String): Map<String, String> {
        val result = LinkedHashMap<String, String>()
        for (rdn in splitUnescaped(dn, ',')) {
            for (ava in splitUnescaped(rdn, '+')) {
                val eq = indexOfUnescaped(ava, '=')
                if (eq <= 0) continue
                val key = ava.substring(0, eq).trim().uppercase()
                val raw = ava.substring(eq + 1).trim()
                val value = if (raw.startsWith("#")) decodeHexDer(raw.substring(1)) else unescape(raw)
                if (value.isNotBlank() && key !in result) result[key] = value.trim()
            }
        }
        return result
    }

    private fun splitUnescaped(s: String, sep: Char): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var esc = false
        var quoted = false
        for (ch in s) {
            when {
                esc -> { sb.append('\\').append(ch); esc = false }
                ch == '\\' -> esc = true
                ch == '"' -> { quoted = !quoted; sb.append(ch) }
                ch == sep && !quoted -> { out += sb.toString(); sb.clear() }
                else -> sb.append(ch)
            }
        }
        if (sb.isNotEmpty()) out += sb.toString()
        return out
    }

    private fun indexOfUnescaped(s: String, target: Char): Int {
        var esc = false
        s.forEachIndexed { i, ch ->
            if (esc) esc = false
            else if (ch == '\\') esc = true
            else if (ch == target) return i
        }
        return -1
    }

    private fun unescape(raw: String): String {
        val v = if (raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"')) raw.substring(1, raw.length - 1) else raw
        val bytes = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < v.length) {
            val ch = v[i]
            if (ch == '\\' && i + 1 < v.length) {
                val n = v[i + 1]
                if (i + 2 < v.length && n.isHex() && v[i + 2].isHex()) {
                    bytes.write(v.substring(i + 1, i + 3).toInt(16)); i += 3; continue
                }
                bytes.write(n.toString().toByteArray(Charsets.UTF_8)); i += 2; continue
            }
            bytes.write(ch.toString().toByteArray(Charsets.UTF_8)); i++
        }
        return bytes.toString(Charsets.UTF_8.name())
    }

    private fun Char.isHex() = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    /** Giải mã một chuỗi ASN.1 đơn giản (UTF8String, PrintableString, IA5String, BMPString...). */
    private fun decodeHexDer(hex: String): String {
        val b = runCatching { hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }.getOrNull() ?: return ""
        if (b.size < 2) return ""
        val tag = b[0].toInt() and 0xff
        var len = b[1].toInt() and 0xff
        var off = 2
        if (len and 0x80 != 0) {
            val n = len and 0x7f
            len = 0
            repeat(n) { len = (len shl 8) or (b[off++].toInt() and 0xff) }
        }
        if (off + len > b.size) return ""
        val body = b.copyOfRange(off, off + len)
        return when (tag) {
            0x1e -> String(body, Charsets.UTF_16BE)
            else -> String(body, Charsets.UTF_8)
        }
    }

    fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
}
