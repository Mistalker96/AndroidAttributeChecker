package com.mixedsignals.checker.domain

import com.mixedsignals.checker.domain.model.AppReport
import com.mixedsignals.checker.domain.model.CERT_RDN_KEYS
import com.mixedsignals.checker.domain.model.MarketField
import com.mixedsignals.checker.domain.model.PackageHistory
import com.mixedsignals.checker.domain.model.RDN_LABELS

/** Một dòng thống kê: count / total, kèm số liệu tương ứng trong paper (nếu có) để so sánh. */
data class RateRow(
    val label: String,
    val count: Int,
    val total: Int,
    val paperValue: String? = null,
) {
    val percent: Double get() = if (total == 0) 0.0 else count * 100.0 / total
    val percentText: String get() = if (total == 0) "—" else String.format(java.util.Locale.US, "%.1f%%", percent)
}

data class StatsSection(val title: String, val note: String, val rows: List<RateRow>)

/**
 * Thống kê trên toàn bộ app của thiết bị, theo đúng cách paper lập Bảng 4 (thiếu tín hiệu)
 * và Bảng 5 (tín hiệu thay đổi), để người dùng so thiết bị của mình với số liệu của paper.
 */
object DeviceStats {

    fun compute(reports: List<AppReport>, histories: Map<String, PackageHistory>): List<StatsSection> {
        val apps = reports.filterNot { it.signals.fromFile }
        return listOf(
            rdnAvailability(apps),
            marketAvailability(apps),
            certProperties(apps),
            volatility(apps, histories),
        )
    }

    private val paperRdnGooglePlay = mapOf(
        "CN" to "7,1%", "O" to "17,6%", "OU" to "27,6%", "L" to "27,2%", "ST" to "28,8%", "C" to "21,8%",
    )

    private fun rdnAvailability(apps: List<AppReport>): StatsSection {
        val withCert = apps.filter { it.signals.currentCerts.isNotEmpty() }
        val rows = CERT_RDN_KEYS.map { k ->
            RateRow(
                "Thiếu $k (${RDN_LABELS[k]})",
                withCert.count { it.signals.currentCerts.first().subject[k].isNullOrBlank() },
                withCert.size,
                paperRdnGooglePlay[k],
            )
        }
        return StatsSection(
            "Độ sẵn có – Subject chứng chỉ (Bảng 4)",
            "Tỷ lệ app có chứng chỉ ký thiếu từng trường subject. Cột paper: Google Play.",
            rows,
        )
    }

    private val paperMarket = mapOf(
        MarketField.DEVELOPER_NAME to "<0,01%",
        MarketField.WEBSITE to "33,7%",
        MarketField.EMAIL to "<0,01%",
        MarketField.ADDRESS to "44,4%",
        MarketField.PRIVACY_POLICY to "17,8%",
    )

    private fun marketAvailability(apps: List<AppReport>): StatsSection {
        val withMarket = apps.filter { it.signals.market?.isEmpty == false }
        val rows = MarketField.entries.map { f ->
            RateRow(
                "Thiếu ${f.label.lowercase()}",
                withMarket.count { it.signals.market?.get(f) == null },
                withMarket.size,
                paperMarket[f],
            )
        }
        return StatsSection(
            "Độ sẵn có – Metadata trên store (Bảng 4)",
            "Chỉ tính các app đã có metadata (tra cứu Google Play hoặc nhập tay): ${withMarket.size} app.",
            rows,
        )
    }

    private fun certProperties(apps: List<AppReport>): StatsSection {
        val n = apps.size
        fun kind(k: CertKind) = apps.count { r -> r.signals.currentCerts.any { CertClassifier.classify(it) == k } }
        val rows = listOf(
            RateRow("Chứng chỉ tự ký", apps.count { r -> r.signals.currentCerts.any { it.selfSigned } }, n, "~99%"),
            RateRow("Ký bằng nhiều scheme", apps.count { it.signals.schemes.size > 1 }, n, "58%"),
            RateRow("Có chữ ký v3 (xoay khóa được)", apps.count { 3 in it.signals.schemes || 31 in it.signals.schemes }, n, "23,1% (Play 29,1%)"),
            RateRow("Chỉ có scheme v1", apps.count { it.signals.schemes == setOf(1) }, n),
            RateRow("Subject mẫu Google / Play Signing", kind(CertKind.GOOGLE_PATTERN), n, "32,4% (Play)"),
            RateRow("Subject giống Google nhưng sai mẫu", kind(CertKind.GOOGLE_LOOKALIKE), n),
            RateRow("Chứng chỉ debug", kind(CertKind.DEBUG), n),
            RateRow("Khóa test AOSP", kind(CertKind.AOSP_TEST), n),
            RateRow("Subject chung chung", kind(CertKind.GENERIC), n),
            RateRow("Đã xoay khóa (lịch sử > 1)", apps.count { it.signals.certHistory.size > 1 }, n),
        )
        return StatsSection("Đặc điểm chứng chỉ (§2.1, §5.2)", "Trên $n app đã quét.", rows)
    }

    private fun volatility(apps: List<AppReport>, histories: Map<String, PackageHistory>): StatsSection {
        // Như paper: chỉ tính app xuất hiện ở ít nhất hai lần quét, so mốc đầu với mốc cuối.
        val tracked = apps.mapNotNull { histories[it.signals.packageName] }.filter { it.scanCount >= 2 }
        val n = tracked.size
        fun firstLast(h: PackageHistory) = h.entries.first() to h.entries.last()
        // Mốc gốc của metadata store là bản ghi đầu tiên có market (lần tra cứu đầu tiên).
        fun marketFirstLast(h: PackageHistory) = h.entries.firstOrNull { it.market != null } to h.entries.last()
        val withMarketBoth = tracked.filter { h ->
            marketFirstLast(h).let { (a, b) -> a != null && a !== b && b.market != null }
        }

        fun marketChanged(f: MarketField) = RateRow(
            "Đổi ${f.label.lowercase()}",
            withMarketBoth.count { h -> marketFirstLast(h).let { (a, b) -> a!!.market!!.get(f) != b.market!!.get(f) } },
            withMarketBoth.size,
            paperVolatility[f],
        )

        fun certRows(c: CertChange, paper: String?) = RateRow(
            "Chứng chỉ: ${c.label.lowercase()}",
            tracked.count { h -> firstLast(h).let { (a, b) -> VolatilityChecks.certChange(a, b) == c } },
            n,
            paper,
        )

        val rows = listOf(
            RateRow("Đổi tên app (manifest)", tracked.count { h -> firstLast(h).let { it.first.label != it.second.label } }, n, "2,5% (tên trên Play)"),
            marketChanged(MarketField.APP_NAME),
            marketChanged(MarketField.DEVELOPER_NAME),
            marketChanged(MarketField.WEBSITE),
            marketChanged(MarketField.EMAIL),
            marketChanged(MarketField.PRIVACY_POLICY),
            certRows(CertChange.ADDED, "0%"),
            certRows(CertChange.REPLACED, "<0,01%"),
            certRows(CertChange.ROTATED, null),
            RateRow(
                "Đổi rồi quay về giá trị cũ",
                tracked.count { h -> VolatilityChecks.revertedSignals(h.entries).isNotEmpty() },
                n,
                "không đo",
            ),
        )
        return StatsSection(
            "Độ biến động (Bảng 5)",
            "So bản ghi đầu tiên với bản ghi mới nhất của $n app đã được quét từ 2 lần trở lên. Cột paper: Google Play.",
            rows,
        )
    }

    private val paperVolatility = mapOf(
        MarketField.APP_NAME to "2,5%",
        MarketField.DEVELOPER_NAME to "3,9%",
        MarketField.WEBSITE to "1,7%",
        MarketField.EMAIL to "1,0%",
        MarketField.PRIVACY_POLICY to "1,6%",
    )
}
