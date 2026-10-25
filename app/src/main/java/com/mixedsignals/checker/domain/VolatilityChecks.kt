package com.mixedsignals.checker.domain

import com.mixedsignals.checker.domain.model.AppSignals
import com.mixedsignals.checker.domain.model.Finding
import com.mixedsignals.checker.domain.model.FindingGroup
import com.mixedsignals.checker.domain.model.MarketField
import com.mixedsignals.checker.domain.model.PackageHistory
import com.mixedsignals.checker.domain.model.Severity
import com.mixedsignals.checker.domain.model.SignalChange
import com.mixedsignals.checker.domain.model.SnapshotEntry
import com.mixedsignals.checker.domain.text.Normalizer

/** Cách chứng chỉ thay đổi giữa hai bản ghi (paper Bảng 5: "Added" / "Fully replaced"). */
enum class CertChange(val label: String) {
    NONE("Không đổi"),
    /** Giữ chứng chỉ cũ và thêm chứng chỉ mới. */
    ADDED("Thêm chứng chỉ"),
    /** Thay hết, nhưng lineage v3 chứng minh khóa mới kế thừa khóa cũ: thay khóa hợp lệ. */
    ROTATED("Xoay khóa (v3)"),
    /** Thay hết và không có liên kết nào với chứng chỉ cũ. */
    REPLACED("Thay hoàn toàn"),
    /** Bỏ một phần, thêm một phần. */
    PARTIAL("Thay một phần"),
}

/** Kiểm tra độ biến động của tín hiệu qua các lần quét (paper §5.2, Bảng 5). */
object VolatilityChecks {

    fun entryOf(s: AppSignals): SnapshotEntry = SnapshotEntry(
        packageName = s.packageName,
        label = s.manifestLabel,
        versionCode = s.versionCode,
        fingerprints = s.currentFingerprints,
        historyFingerprints = s.historyFingerprints,
        market = s.market?.takeUnless { it.isEmpty },
        scannedAt = s.scannedAt,
    )

    /** true nếu có ít nhất một tín hiệu attribution khác nhau (phiên bản app không tính). */
    fun signalsDiffer(a: SnapshotEntry, b: SnapshotEntry): Boolean =
        a.label != b.label || a.fingerprints != b.fingerprints ||
            a.historyFingerprints != b.historyFingerprints || marketDiffers(a, b)

    private fun marketDiffers(a: SnapshotEntry, b: SnapshotEntry): Boolean {
        val mb = b.market ?: return false
        // Lần đầu có metadata cũng là thông tin mới cần ghi lại (dù không tính là "thay đổi").
        val ma = a.market ?: return true
        return MarketField.entries.any { ma.get(it) != mb.get(it) }
    }

    /**
     * Lịch sử sau khi ghi nhận tín hiệu hiện tại: chỉ thêm bản ghi mới khi có tín hiệu thay đổi.
     * @param countAsScan false khi chỉ cập nhật metadata store (không phải một lần quét mới).
     */
    fun updatedHistory(s: AppSignals, old: PackageHistory?, countAsScan: Boolean = true): PackageHistory {
        val cur = entryOf(s)
        if (old == null || old.entries.isEmpty()) {
            return PackageHistory(s.packageName, listOf(cur), 1, s.scannedAt, s.scannedAt)
        }
        val last = old.entries.last()
        // Nếu lần này không có market metadata thì giữ market của lần trước, tránh coi là "bị xóa".
        val merged = if (cur.market == null) cur.copy(market = last.market) else cur
        val entries = if (signalsDiffer(last, merged)) old.entries + merged else old.entries
        return old.copy(
            entries = entries.takeLast(MAX_ENTRIES),
            scanCount = if (countAsScan) old.scanCount + 1 else old.scanCount,
            lastSeen = if (countAsScan) s.scannedAt else old.lastSeen,
        )
    }

    fun certChange(prev: SnapshotEntry, cur: SnapshotEntry): CertChange {
        val a = prev.fingerprints
        val b = cur.fingerprints
        return when {
            a == b -> CertChange.NONE
            b.containsAll(a) -> CertChange.ADDED
            a.intersect(b).isEmpty() ->
                if (cur.historyFingerprints.intersect(a).isNotEmpty()) CertChange.ROTATED else CertChange.REPLACED
            else -> CertChange.PARTIAL
        }
    }

    /** Liệt kê mọi thay đổi giữa các bản ghi liên tiếp. */
    fun changes(entries: List<SnapshotEntry>): List<SignalChange> {
        val out = mutableListOf<SignalChange>()
        for (i in 1 until entries.size) {
            val p = entries[i - 1]
            val c = entries[i]
            if (p.label != c.label) out += SignalChange(SIG_LABEL, p.label, c.label, c.scannedAt)
            val cc = certChange(p, c)
            if (cc != CertChange.NONE) {
                out += SignalChange(
                    "$SIG_CERT: ${cc.label}",
                    p.fingerprints.joinToString { it.take(12) },
                    c.fingerprints.joinToString { it.take(12) },
                    c.scannedAt,
                )
            }
            val pm = p.market
            val cm = c.market
            if (pm != null && cm != null) {
                for (f in MarketField.entries) {
                    val x = pm.get(f)
                    val y = cm.get(f)
                    if (x != y) out += SignalChange(f.label, x ?: "(trống)", y ?: "(trống)", c.scannedAt)
                }
            }
        }
        return out
    }

    fun run(entries: List<SnapshotEntry>): List<Finding> {
        if (entries.size < 2) return emptyList()
        val out = mutableListOf<Finding>()
        val prev = entries[entries.size - 2]
        val cur = entries.last()

        when (certChange(prev, cur)) {
            CertChange.REPLACED -> out += f(
                "CHANGED_CERT_REPLACED", Severity.HIGH, "Chứng chỉ ký bị thay hoàn toàn",
                "Chứng chỉ mới không có liên kết lineage nào với chứng chỉ cũ. Có thể là tác giả tái phát hành, " +
                    "hoặc một tác giả khác đăng lại cùng package name (paper: ví dụ ua.iread.android).", "§5.2",
            )
            CertChange.PARTIAL -> out += f(
                "CHANGED_CERT_PARTIAL", Severity.MEDIUM, "Bộ chứng chỉ ký thay đổi một phần",
                "Một số chứng chỉ bị bỏ và có chứng chỉ mới xuất hiện.", "§5.2",
            )
            CertChange.ADDED -> out += f(
                "CHANGED_CERT_ADDED", Severity.LOW, "Thêm chứng chỉ ký mới",
                "Chứng chỉ cũ vẫn còn, có thêm chứng chỉ mới.", "§5.2",
            )
            CertChange.ROTATED -> out += f(
                "CHANGED_CERT_ROTATED", Severity.INFO, "Đã xoay khóa ký hợp lệ (v3)",
                "Chứng chỉ mới chứng minh được kế thừa chứng chỉ cũ qua lineage v3.", "§5.2",
            )
            CertChange.NONE -> Unit
        }

        // Đếm số lần đổi của từng tín hiệu trên toàn bộ dòng thời gian.
        val reverts = revertedSignals(entries)
        for ((signal, list) in changesBySignal(entries)) {
            val baseline = valueOf(baselineFor(entries, signal), signal)
            val now = valueOf(cur, signal)
            val reverted = signal in reverts
            val isDev = signal == MarketField.DEVELOPER_NAME.label
            val sev = when {
                reverted -> Severity.INFO
                list.size >= 3 -> Severity.MEDIUM
                isDev -> Severity.MEDIUM
                else -> Severity.LOW
            }
            val title = when {
                reverted -> "$signal đã đổi rồi quay về giá trị ban đầu"
                else -> "$signal thay đổi ${list.size} lần"
            }
            val detail = buildString {
                append("Ban đầu: \"${baseline ?: "(trống)"}\" → hiện tại: \"${now ?: "(trống)"}\".")
                if (reverted) append(" Paper bỏ qua các trường hợp này khi chỉ so mốc đầu và mốc cuối; app vẫn ghi lại.")
                if (list.size >= 3) append(" Biến động cao (paper: có app đổi tên 6 lần, developer đổi tên 4 lần).")
            }
            out += f("CHANGED_" + signalId(signal), sev, title, detail, "§5.2")
        }
        return out
    }

    /** Các thay đổi (trừ chứng chỉ) gom theo tín hiệu. */
    private fun changesBySignal(entries: List<SnapshotEntry>): Map<String, List<SignalChange>> =
        changes(entries).filterNot { it.signal.startsWith(SIG_CERT) }.groupBy { it.signal }

    /**
     * Tín hiệu đã thay đổi ít nhất một lần nhưng giá trị hiện tại trùng mốc gốc.
     * Paper chỉ so mốc đầu với mốc cuối nên không thấy các trường hợp này (§5.2).
     */
    fun revertedSignals(entries: List<SnapshotEntry>): Set<String> {
        if (entries.size < 2) return emptySet()
        return changesBySignal(entries).keys.filter { signal ->
            Normalizer.same(valueOf(baselineFor(entries, signal), signal), valueOf(entries.last(), signal))
        }.toSet()
    }

    /**
     * Mốc gốc của một tín hiệu: bản ghi đầu tiên có tín hiệu đó. Với metadata store,
     * các bản ghi trước lần tra cứu đầu tiên không có market nên bị bỏ qua.
     */
    fun baselineFor(entries: List<SnapshotEntry>, signal: String): SnapshotEntry =
        if (signal == SIG_LABEL || signal.startsWith(SIG_CERT)) entries.first()
        else entries.firstOrNull { it.market != null } ?: entries.first()

    private fun valueOf(e: SnapshotEntry, signal: String): String? =
        if (signal == SIG_LABEL) e.label
        else MarketField.entries.firstOrNull { it.label == signal }?.let { e.market?.get(it) }

    private fun signalId(signal: String): String =
        if (signal == SIG_LABEL) "LABEL"
        else MarketField.entries.firstOrNull { it.label == signal }?.name ?: "OTHER"

    private fun f(id: String, sev: Severity, title: String, detail: String, ref: String) =
        Finding(id, FindingGroup.VOLATILITY, sev, title, detail, ref)

    const val SIG_LABEL = "Tên app (manifest)"
    const val SIG_CERT = "Chứng chỉ ký"
    private const val MAX_ENTRIES = 50
}
