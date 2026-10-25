package com.mixedsignals.checker.data.integrity

import com.mixedsignals.checker.domain.integrity.CheckStatus
import com.mixedsignals.checker.domain.integrity.LocalLog
import com.mixedsignals.checker.domain.integrity.LocalLogEntry
import com.mixedsignals.checker.domain.integrity.LogCheckResult
import com.mixedsignals.checker.domain.integrity.Rekor
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Tra Sigstore Rekor theo SHA-256 của file (chỉ gửi hash, không gửi file). */
object RekorClient {
    fun check(fileSha256: String, progress: (String) -> Unit = {}): LogCheckResult {
        progress("Đang tra log công khai Sigstore Rekor…")
        val uuids = try {
            JSONArray(String(Http.postJson("${Rekor.BASE_URL}/index/retrieve", """{"hash":"sha256:${fileSha256.lowercase()}"}""")))
        } catch (e: Exception) {
            return LogCheckResult(CheckStatus.UNKNOWN, "Không tra được Rekor: ${e.message}")
        }
        if (uuids.length() == 0) {
            return LogCheckResult(CheckStatus.NA, "Developer chưa ghi chữ ký file này lên log công khai Sigstore Rekor.")
        }
        val problems = mutableListOf<String>()
        for (i in 0 until minOf(uuids.length(), 5)) {
            val uuid = uuids.getString(i)
            val entry = try {
                Rekor.parseEntry(String(Http.get("${Rekor.BASE_URL}/log/entries/$uuid")))
            } catch (e: Exception) {
                problems += "Không đọc được bản ghi ${uuid.take(12)}…: ${e.message}"; continue
            }
            val err = Rekor.verifyEntry(entry, fileSha256)
            if (err == null) {
                val time = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault()).format(Date(entry.integratedTime * 1000))
                return LogCheckResult(
                    CheckStatus.PASS,
                    "đã xác minh bằng chứng Merkle và checkpoint có chữ ký của Rekor; người ký: ${entry.signer ?: "không rõ"}.",
                    listOf(
                        "Bản ghi: ${entry.uuid.take(24)}… (loại ${entry.kind}), vị trí ${entry.logIndex}",
                        "Thời điểm ghi log: $time",
                        "Người ký trên Rekor: ${entry.signer ?: "không rõ"} — hãy đối chiếu với danh tính developer công bố.",
                    ),
                )
            }
            problems += "Bản ghi ${uuid.take(12)}…: $err"
        }
        return LogCheckResult(CheckStatus.UNKNOWN, "Tìm thấy bản ghi trên Rekor nhưng không xác minh được.", problems)
    }
}

/** Lưu nhật ký minh bạch cục bộ (chuỗi băm chỉ-thêm) trong bộ nhớ riêng của app. */
class LocalLogStore(private val file: File) {
    @Synchronized
    fun load(): List<LocalLogEntry> {
        if (!file.exists()) return emptyList()
        val arr = runCatching { JSONArray(file.readText()) }.getOrNull() ?: return emptyList()
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            val s = o.getJSONArray("signers")
            LocalLogEntry(
                o.getLong("seq"), o.getLong("time"), o.getString("pkg"), o.getLong("vc"), o.getString("sha"),
                (0 until s.length()).map { s.getString(it) }.toSet(), o.getString("prev"), o.getString("hash"),
            )
        }
    }

    @Synchronized
    fun append(pkg: String, vc: Long, sha: String, signers: Set<String>) {
        val log = load()
        // Không ghi trùng một file đã có trong nhật ký.
        if (log.any { it.packageName == pkg && it.versionCode == vc && it.fileSha256 == sha }) return
        val e = LocalLog.append(log, System.currentTimeMillis(), pkg, vc, sha, signers)
        val arr = JSONArray()
        (log + e).forEach { x ->
            arr.put(JSONObject().apply {
                put("seq", x.seq); put("time", x.time); put("pkg", x.packageName); put("vc", x.versionCode)
                put("sha", x.fileSha256); put("signers", JSONArray(x.signers.toList())); put("prev", x.prevHash); put("hash", x.hash)
            })
        }
        file.writeText(arr.toString())
    }
}
