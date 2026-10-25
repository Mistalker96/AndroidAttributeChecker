package com.mixedsignals.checker.domain.integrity

import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Kiểm tra Code Transparency của App Bundle, theo logic của `bundletool check-transparency`:
 *  1. File `META-INF/code_transparency_signed.jwt` là JWS (RS256), chứng chỉ khóa nằm ở header `x5c`.
 *  2. Nội dung JSON: `codeRelatedFile[{path, type (DEX|NATIVE_LIBRARY), apkPath, sha256}]`.
 *  3. Mọi file `.dex` trong APK phải có hash nằm trong danh sách DEX; mọi file `.so` phải khớp hash theo `apkPath`.
 *  4. Khóa phải được "neo": khớp fingerprint do developer công bố hoặc khớp lần kiểm trước.
 */
object CodeTransparency {
    const val ENTRY_NAME = "META-INF/code_transparency_signed.jwt"

    data class Parsed(
        val keyCert: X509Certificate,
        val keyFingerprint: String,
        val signatureValid: Boolean,
        val dexHashes: Set<String>,
        val nativeByApkPath: Map<String, String>,
        val version: Int,
    )

    private fun b64url(s: String): ByteArray = Base64.getUrlDecoder().decode(s.trim())

    fun parse(jws: String): Parsed {
        val parts = jws.trim().split('.')
        require(parts.size == 3) { "JWS phải có 3 phần" }
        val header = JSONObject(String(b64url(parts[0])))
        require(header.optString("alg") == "RS256") { "Chỉ chấp nhận thuật toán RS256 (như bundletool)" }
        val x5c = header.getJSONArray("x5c")
        val der = Base64.getDecoder().decode(x5c.getString(0))
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val fp = MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") { "%02x".format(it) }

        val signingInput = "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII)
        val valid = runCatching {
            Signature.getInstance("SHA256withRSA").run {
                initVerify(cert.publicKey); update(signingInput); verify(b64url(parts[2]))
            }
        }.getOrDefault(false)

        val payload = JSONObject(String(b64url(parts[1]), Charsets.UTF_8))
        val files = payload.optJSONArray("codeRelatedFile")
        val dex = mutableSetOf<String>()
        val native = mutableMapOf<String, String>()
        if (files != null) for (i in 0 until files.length()) {
            val f = files.getJSONObject(i)
            val type = f.optString("type", "TYPE_UNSPECIFIED")
            val sha = f.optString("sha256").lowercase()
            val path = f.optString("path")
            when {
                type == "DEX" || (type == "TYPE_UNSPECIFIED" && path.endsWith(".dex")) -> dex += sha
                type == "NATIVE_LIBRARY" -> native[f.optString("apkPath")] = sha
            }
        }
        return Parsed(cert, fp, valid, dex, native, payload.optInt("version", 0))
    }

    /**
     * @param jws nội dung file JWT trong base APK, hoặc null nếu không có.
     * @param apkEntries với mỗi APK (base + các split có mặt): tên entry → SHA-256 (hex) của các file .dex và .so.
     * @param expectedSplitsMissing true nếu biết là còn split vắng mặt (chỉ có một file APK của app chia nhỏ).
     * @param publishedKeys fingerprint khóa Code Transparency do developer công bố (có thể rỗng).
     * @param previousKey khóa đã ghi nhận ở lần kiểm trước (có thể null).
     * @param apkSignerFingerprints fingerprint khóa ký APK (khóa CT trùng khóa này thì không thêm bằng chứng).
     */
    fun verify(
        jws: String?,
        apkEntries: Map<String, Map<String, String>>,
        expectedSplitsMissing: Boolean,
        publishedKeys: Set<String>,
        previousKey: String?,
        apkSignerFingerprints: Set<String>,
    ): CodeTransparencyResult {
        if (jws == null) return CodeTransparencyResult(CheckStatus.NA, "APK không có Code Transparency (tính năng tùy chọn, ít app dùng).")
        val p = try {
            parse(jws)
        } catch (e: Exception) {
            return CodeTransparencyResult(CheckStatus.FAIL, "File Code Transparency hỏng hoặc sai định dạng: ${e.message}")
        }
        if (!p.signatureValid) {
            return CodeTransparencyResult(CheckStatus.FAIL, "Chữ ký Code Transparency KHÔNG hợp lệ.", p.keyFingerprint)
        }
        if (p.version > 1) {
            return CodeTransparencyResult(CheckStatus.UNKNOWN, "Phiên bản Code Transparency ${p.version} chưa được hỗ trợ.", p.keyFingerprint)
        }
        val modified = mutableListOf<String>()
        var checked = 0
        for ((apk, entries) in apkEntries) {
            for ((name, sha) in entries) {
                when {
                    name.endsWith(".dex") -> { checked++; if (sha.lowercase() !in p.dexHashes) modified += "$apk!$name" }
                    name.endsWith(".so") -> { checked++; if (p.nativeByApkPath[name] != sha.lowercase()) modified += "$apk!$name" }
                }
            }
        }
        val presentNative = apkEntries.values.flatMap { it.keys }.toSet()
        val missing = p.nativeByApkPath.keys.count { it !in presentNative }

        val norm = publishedKeys.map { it.lowercase().replace(":", "").replace(" ", "") }.toSet()
        if (norm.isNotEmpty() && p.keyFingerprint !in norm) {
            return CodeTransparencyResult(CheckStatus.FAIL, "Khóa Code Transparency KHÁC khóa developer công bố.", p.keyFingerprint, false, checked, missing, modified)
        }
        if (previousKey != null && previousKey != p.keyFingerprint) {
            return CodeTransparencyResult(CheckStatus.FAIL, "Khóa Code Transparency KHÁC lần kiểm trước.", p.keyFingerprint, false, checked, missing, modified)
        }
        if (modified.isNotEmpty()) {
            return CodeTransparencyResult(CheckStatus.FAIL, "Code bị sửa sau khi developer ký: ${modified.size} file không khớp.", p.keyFingerprint, false, checked, missing, modified)
        }
        if (checked == 0) {
            return CodeTransparencyResult(CheckStatus.UNKNOWN, "Không tìm thấy file code nào để so (thiếu split?).", p.keyFingerprint, false, 0, missing)
        }
        val anchored = p.keyFingerprint in norm || previousKey == p.keyFingerprint
        val sameAsApkKey = p.keyFingerprint in apkSignerFingerprints
        val summary = buildString {
            append("Code khớp với bản developer đã ký ($checked file).")
            if (expectedSplitsMissing || missing > 0) append(" Một phần code nằm ở split vắng mặt nên chưa kiểm được.")
            append(
                when {
                    sameAsApkKey -> " Khóa Code Transparency trùng khóa ký APK nên không thêm bằng chứng độc lập."
                    anchored -> " Khóa đã được neo."
                    else -> " Khóa chưa được neo: lần đầu thấy, chưa có fingerprint công bố."
                },
            )
        }
        return CodeTransparencyResult(CheckStatus.PASS, summary, p.keyFingerprint, anchored && !sameAsApkKey, checked, missing)
    }
}
