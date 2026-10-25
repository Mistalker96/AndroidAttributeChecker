package com.mixedsignals.checker.domain

import com.mixedsignals.checker.domain.model.AppReport
import com.mixedsignals.checker.domain.model.MarketField
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Xuất báo cáo dạng Markdown (dễ đọc, dán vào báo cáo hoặc issue). */
object MarkdownReport {
    private fun date(t: Long) = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(t))

    fun build(reports: List<AppReport>, stats: List<StatsSection>, generatedAt: Long): String = buildString {
        appendLine("# Báo cáo Attribution Checker")
        appendLine()
        appendLine("Thời điểm: ${date(generatedAt)} · Số app: ${reports.size}")
        appendLine()
        appendLine("> Dựa trên đóng góp 1 của paper *Mixed Signals* (§5): độ sẵn có và độ biến động của tín hiệu attribution.")
        appendLine("> Điểm phản ánh mức đầy đủ và ổn định của tín hiệu tự khai, **không** phải mức an toàn của app.")
        appendLine()
        appendLine("## Thống kê trên thiết bị")
        for (sec in stats) {
            appendLine()
            appendLine("### ${sec.title}")
            appendLine()
            appendLine(sec.note)
            appendLine()
            appendLine("| Chỉ số | Số app | Tỷ lệ | Paper |")
            appendLine("|---|---:|---:|---:|")
            for (r in sec.rows) appendLine("| ${r.label} | ${r.count}/${r.total} | ${r.percentText} | ${r.paperValue ?: ""} |")
        }
        appendLine()
        appendLine("## Chi tiết từng app")
        for (r in reports.sortedBy { it.score }) {
            val s = r.signals
            appendLine()
            appendLine("### ${esc(s.manifestLabel)} — `${s.packageName}`")
            appendLine()
            appendLine("- Điểm: **${r.score}/100** (${r.level.label})")
            appendLine("- Phiên bản: ${s.versionName ?: "?"} (${s.versionCode})")
            appendLine("- Scheme chữ ký: ${s.schemes.sorted().joinToString { AvailabilityChecks.schemeName(it) }.ifEmpty { "không rõ" }}")
            s.currentCerts.forEach { c ->
                appendLine("- Chứng chỉ `${c.sha256}`: ${esc(c.subjectString)}")
            }
            s.market?.takeUnless { it.isEmpty }?.let { m ->
                appendLine("- Metadata store (${m.source}): " + MarketField.entries.joinToString("; ") { "${it.label}: ${esc(m.get(it) ?: "—")}" })
            }
            if (r.findings.isNotEmpty()) {
                appendLine()
                appendLine("| Mức | Nhóm | Phát hiện | Paper |")
                appendLine("|---|---|---|---|")
                r.findings.forEach { f ->
                    appendLine("| ${f.severity.label} | ${f.group.label} | ${esc(f.title)} | ${f.paperRef} |")
                }
            }
            if (r.changes.isNotEmpty()) {
                appendLine()
                appendLine("Lịch sử thay đổi:")
                r.changes.forEach { c -> appendLine("- ${date(c.at)} · ${c.signal}: \"${esc(c.from)}\" → \"${esc(c.to)}\"") }
            }
        }
    }

    private fun esc(s: String) = s.replace("|", "\\|").replace("\n", " ")
}
