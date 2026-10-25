package com.mixedsignals.checker.domain.integrity

import org.json.JSONArray
import org.json.JSONObject

/** Bộ đọc dữ liệu của các nguồn công bố (thuần, kiểm thử được). */
object SourceParsers {

    fun normalizeFingerprint(s: String): String = s.lowercase().replace(":", "").replace(" ", "").trim()

    /** Fingerprint hợp lệ: 64 ký tự hex. */
    fun isFingerprint(s: String): Boolean = normalizeFingerprint(s).matches(Regex("[0-9a-f]{64}"))

    /** Tách các fingerprint SHA-256 người dùng dán vào (cách nhau bởi dòng, dấu phẩy, khoảng trắng). */
    fun parseUserFingerprints(text: String): Set<String> =
        Regex("(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{64}").findAll(text).map { normalizeFingerprint(it.value) }.toSet()

    /**
     * Digital Asset Links (`/.well-known/assetlinks.json`): trả về các fingerprint khai cho [packageName].
     * Rỗng nếu file không có mục nào cho package.
     */
    fun assetLinksFingerprints(json: String, packageName: String): Set<String> {
        val arr = JSONArray(json)
        val out = mutableSetOf<String>()
        for (i in 0 until arr.length()) {
            val target = arr.optJSONObject(i)?.optJSONObject("target") ?: continue
            if (target.optString("namespace") != "android_app" || target.optString("package_name") != packageName) continue
            val fps = target.optJSONArray("sha256_cert_fingerprints") ?: continue
            for (j in 0 until fps.length()) out += normalizeFingerprint(fps.getString(j))
        }
        return out
    }

    /** F-Droid `signer-index.json`: package → fingerprint khóa ký chính thức trên f-droid.org. */
    fun fdroidSigner(json: String, packageName: String): String? =
        JSONObject(json).optJSONObject(packageName)?.optString("signer")?.takeIf { it.isNotBlank() }?.let(::normalizeFingerprint)

    /** Kết quả một báo cáo build lại của F-Droid (verification.f-droid.org/…apk.json). */
    data class FdroidVerification(val verified: Boolean, val publishedSha256: String?)

    fun fdroidVerification(json: String): List<FdroidVerification> {
        val o = JSONObject(json)
        return o.keys().asSequence().mapNotNull { k ->
            val r = o.optJSONObject(k) ?: return@mapNotNull null
            if (!r.has("verified")) return@mapNotNull null
            FdroidVerification(r.optBoolean("verified"), r.optJSONObject("remote")?.optString("sha256")?.lowercase())
        }.toList()
    }

    /** Một bản ghi trong chỉ mục reproducible build của IzzyOnDroid (rbtlog index.json, khóa = SHA-256 file APK). */
    data class IzzyRecord(val appId: String, val versionCode: Long, val reproducible: Boolean?, val repository: String?)

    fun izzyLookup(indexJson: String, fileSha256: String): List<IzzyRecord> {
        val arr = JSONObject(indexJson).optJSONArray(fileSha256.lowercase()) ?: return emptyList()
        return (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i)
            IzzyRecord(
                e.optString("appid"),
                e.optLong("version_code"),
                if (e.isNull("reproducible")) null else e.optBoolean("reproducible"),
                e.optString("repository").ifBlank { null },
            )
        }
    }

    /** Bản ghi của transparency log Google cho app: `<sha256>\nSHA256(APK)\n<package>\n<versionCode>\n`. */
    fun googleApkPayload(fileSha256: String, packageName: String, versionCode: Long): String =
        "${fileSha256.lowercase()}\nSHA256(APK)\n$packageName\n$versionCode\n"

    /** Tách gói bản ghi (entry bundle) theo tlog-tiles: chuỗi bản ghi có tiền tố độ dài 2 byte big-endian. */
    fun parseEntryBundle(data: ByteArray): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        var i = 0
        while (i + 2 <= data.size) {
            val len = ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
            i += 2
            require(i + len <= data.size) { "Gói bản ghi bị cắt cụt" }
            out += data.copyOfRange(i, i + len)
            i += len
        }
        return out
    }

    /** Đường dẫn tile theo tlog-tiles: N=1234067 → "x001/x234/067". */
    fun tileIndexPath(n: Long): String {
        val groups = mutableListOf<Long>()
        var x = n
        do { groups += x % 1000; x /= 1000 } while (x > 0)
        groups.reverse()
        return groups.mapIndexed { i, g -> (if (i < groups.size - 1) "x" else "") + "%03d".format(g) }.joinToString("/")
    }
}
