package com.mixedsignals.checker.domain.integrity

import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Sigstore Rekor: transparency log công khai (cây Merkle RFC 6962/9162) mà BẤT KỲ developer nào cũng ghi được
 * chữ ký của file phát hành (ví dụ `cosign sign-blob app.apk`). Dùng làm kiểm tra tương đương khi app không có
 * trong log của Google.
 */
object Rekor {
    const val BASE_URL = "https://rekor.sigstore.dev/api/v1"

    /** Khóa công khai của Rekor (ECDSA P-256), lấy từ /api/v1/log/publicKey; mã khóa c0d23d6a. */
    const val PUBLIC_KEY_B64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="

    data class Proof(val logIndex: Long, val treeSize: Long, val rootHash: ByteArray, val hashes: List<ByteArray>, val checkpoint: String)

    data class Entry(
        val uuid: String,
        val body: ByteArray,
        val kind: String,
        val dataHash: String?,
        val integratedTime: Long,
        val logIndex: Long,
        val proof: Proof?,
        /** Danh tính người ký (email/URI trong chứng chỉ Fulcio, hoặc loại khóa). */
        val signer: String?,
    )

    private fun sha256(vararg p: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256"); p.forEach { md.update(it) }; return md.digest()
    }

    /** Xác minh bằng chứng inclusion theo RFC 9162 §2.1.3.2. */
    fun verifyInclusion(leafHash: ByteArray, index: Long, treeSize: Long, proof: List<ByteArray>, root: ByteArray): Boolean {
        if (index < 0 || index >= treeSize) return false
        var fn = index
        var sn = treeSize - 1
        var r = leafHash
        for (p in proof) {
            if (sn == 0L) return false
            if (fn % 2 == 1L || fn == sn) {
                r = Merkle.nodeHash(p, r)
                while (fn % 2 == 0L && fn != 0L) { fn = fn shr 1; sn = sn shr 1 }
            } else {
                r = Merkle.nodeHash(r, p)
            }
            fn = fn shr 1; sn = sn shr 1
        }
        return sn == 0L && r.contentEquals(root)
    }

    fun publicKey(): PublicKey =
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY_B64)))

    /** Xác minh checkpoint (signed note) của Rekor bằng ECDSA; trả về (kích thước cây, gốc). */
    fun verifyCheckpoint(note: String, key: PublicKey = publicKey()): Pair<Long, ByteArray> {
        val sep = note.indexOf("\n\n")
        require(sep > 0) { "Checkpoint không có chữ ký" }
        val body = note.substring(0, sep + 1)
        val keyHash = sha256(key.encoded).copyOf(4)
        val ok = note.substring(sep + 2).lines().filter { it.startsWith("— ") }.any { line ->
            val sigB64 = line.substringAfterLast(' ')
            val sig = runCatching { Base64.getDecoder().decode(sigB64) }.getOrNull() ?: return@any false
            sig.size > 4 && sig.copyOf(4).contentEquals(keyHash) && runCatching {
                Signature.getInstance("SHA256withECDSA").run {
                    initVerify(key); update(body.toByteArray()); verify(sig.copyOfRange(4, sig.size))
                }
            }.getOrDefault(false)
        }
        require(ok) { "Chữ ký checkpoint của Rekor không hợp lệ" }
        val lines = body.trimEnd('\n').lines()
        require(lines.size >= 3 && lines[0].startsWith("rekor.sigstore.dev")) { "Checkpoint sai định dạng" }
        return lines[1].toLong() to Base64.getDecoder().decode(lines[2])
    }

    /** Đọc một bản ghi từ phản hồi GET /log/entries/{uuid} (dạng {uuid: {...}}). */
    fun parseEntry(json: String): Entry {
        val root = JSONObject(json)
        val uuid = root.keys().next()
        val e = root.getJSONObject(uuid)
        val body = Base64.getDecoder().decode(e.getString("body"))
        val b = JSONObject(String(body))
        val spec = b.optJSONObject("spec")
        val p = e.optJSONObject("verification")?.optJSONObject("inclusionProof")
        val proof = p?.let {
            val hs = it.getJSONArray("hashes")
            Proof(
                it.getLong("logIndex"), it.getLong("treeSize"), hex(it.getString("rootHash")),
                (0 until hs.length()).map { i -> hex(hs.getString(i)) }, it.getString("checkpoint"),
            )
        }
        return Entry(
            uuid, body, b.optString("kind"),
            spec?.optJSONObject("data")?.optJSONObject("hash")?.optString("value")?.lowercase(),
            e.optLong("integratedTime"), e.optLong("logIndex"), proof,
            spec?.optJSONObject("signature")?.optJSONObject("publicKey")?.optString("content")?.let(::signerOf),
        )
    }

    /** Lấy danh tính từ chứng chỉ (Fulcio: email hoặc URI trong SAN); nếu không phải chứng chỉ thì chỉ ghi “khóa công khai”. */
    fun signerOf(contentB64: String): String = runCatching {
        val pem = String(Base64.getDecoder().decode(contentB64))
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(pem.toByteArray())) as X509Certificate
        cert.subjectAlternativeNames?.mapNotNull { it.getOrNull(1)?.toString() }?.firstOrNull()
            ?: cert.subjectX500Principal.name
    }.getOrDefault("khóa công khai (không có chứng chỉ danh tính)")

    /** Kiểm một bản ghi: hash dữ liệu khớp file, bằng chứng Merkle đúng, checkpoint có chữ ký hợp lệ. */
    fun verifyEntry(e: Entry, fileSha256: String): String? {
        if (e.dataHash != fileSha256.lowercase()) return "hash trong bản ghi khác hash file"
        val p = e.proof ?: return "bản ghi không kèm bằng chứng inclusion"
        val leaf = Merkle.leafHash(e.body)
        if (!verifyInclusion(leaf, p.logIndex, p.treeSize, p.hashes, p.rootHash)) return "bằng chứng Merkle không khớp gốc"
        val (size, root) = runCatching { verifyCheckpoint(p.checkpoint) }.getOrElse { return it.message }
        if (size != p.treeSize || !root.contentEquals(p.rootHash)) return "checkpoint không khớp bằng chứng"
        return null
    }

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
