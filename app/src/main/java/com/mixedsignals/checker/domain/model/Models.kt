package com.mixedsignals.checker.domain.model

/**
 * Mô hình dữ liệu thuần Kotlin (không phụ thuộc Android) để kiểm thử được trên JVM.
 * Tên tín hiệu bám theo §3 của paper "Mixed Signals"; app này hiện thực đóng góp 1 (§5):
 * độ sẵn có (availability) và độ biến động (volatility) của tín hiệu attribution.
 */

/** Các RDN của subject chứng chỉ mà paper đo ở Bảng 4. */
val CERT_RDN_KEYS = listOf("CN", "O", "OU", "L", "ST", "C")

val RDN_LABELS = mapOf(
    "CN" to "commonName",
    "O" to "organization",
    "OU" to "organizationalUnit",
    "L" to "locality",
    "ST" to "state",
    "C" to "country",
    "EMAILADDRESS" to "email",
)

/** Một chứng chỉ X.509 dùng để ký APK. */
data class CertInfo(
    val sha256: String,
    /** RDN của subject, khóa viết hoa: CN, O, OU, L, ST, C, EMAILADDRESS... Giá trị rỗng bị loại bỏ. */
    val subject: Map<String, String>,
    val issuer: Map<String, String>,
    val selfSigned: Boolean,
    val notBefore: Long,
    val notAfter: Long,
    val sigAlg: String,
    val keyAlg: String,
    val keySizeBits: Int?,
) {
    val subjectString: String
        get() = subject.entries.joinToString(", ") { "${it.key}=${it.value}" }.ifEmpty { "(trống)" }
    val missingRdns: List<String> get() = CERT_RDN_KEYS.filter { subject[it].isNullOrBlank() }
}

/** Các trường market metadata paper đo trên Google Play (Bảng 4). */
enum class MarketField(val label: String) {
    APP_NAME("Tên app trên store"),
    DEVELOPER_NAME("Tên developer"),
    WEBSITE("Website developer"),
    EMAIL("Email developer"),
    ADDRESS("Địa chỉ developer"),
    PRIVACY_POLICY("URL privacy policy"),
}

/** Tín hiệu lấy từ market profile (nhập tay hoặc tra cứu Google Play). */
data class MarketSignals(
    val appName: String? = null,
    val developerName: String? = null,
    val website: String? = null,
    val email: String? = null,
    val address: String? = null,
    val privacyPolicyUrl: String? = null,
    /** "manual" (nhập tay) hoặc "play" (tra cứu Google Play). */
    val source: String = "manual",
    val fetchedAt: Long = 0L,
) {
    fun get(f: MarketField): String? = when (f) {
        MarketField.APP_NAME -> appName
        MarketField.DEVELOPER_NAME -> developerName
        MarketField.WEBSITE -> website
        MarketField.EMAIL -> email
        MarketField.ADDRESS -> address
        MarketField.PRIVACY_POLICY -> privacyPolicyUrl
    }?.takeIf { it.isNotBlank() }

    val isEmpty: Boolean get() = MarketField.entries.all { get(it) == null }
}

/** Toàn bộ tín hiệu attribution thu được cho một app tại một thời điểm. */
data class AppSignals(
    val packageName: String,
    val manifestLabel: String,
    val versionName: String?,
    val versionCode: Long,
    /** Package của trình cài đặt; null nếu không rõ hoặc là file APK rời. */
    val installer: String?,
    val isSystemApp: Boolean,
    /** true nếu phân tích từ một file .apk chưa cài. */
    val fromFile: Boolean,
    /** Scheme chữ ký có trong file: 1, 2, 3 và 31 (v3.1). */
    val schemes: Set<Int>,
    val currentCerts: List<CertInfo>,
    /** Lịch sử xoay khóa (v3), chứng chỉ gốc ở đầu danh sách. Rỗng nếu không có. */
    val certHistory: List<CertInfo>,
    val hasMultipleSigners: Boolean,
    val market: MarketSignals? = null,
    val scannedAt: Long = System.currentTimeMillis(),
) {
    val currentFingerprints: Set<String> get() = currentCerts.map { it.sha256 }.toSet()
    val historyFingerprints: Set<String> get() = certHistory.map { it.sha256 }.toSet()
}

enum class Severity(val weight: Int, val label: String) {
    HIGH(25, "Cao"),
    MEDIUM(10, "Trung bình"),
    LOW(4, "Thấp"),
    INFO(0, "Thông tin"),
}

enum class FindingGroup(val label: String) {
    AVAILABILITY("Độ sẵn có"),
    VOLATILITY("Độ biến động"),
}

/** Một phát hiện của bộ kiểm tra. */
data class Finding(
    val id: String,
    val group: FindingGroup,
    val severity: Severity,
    val title: String,
    val detail: String,
    /** Mục tương ứng trong paper, ví dụ "§5.1". */
    val paperRef: String,
)

/**
 * Bản ghi tín hiệu của một app ở một lần quét, lưu lại để đo biến động (§5.2).
 * Chỉ ghi bản mới khi có ít nhất một tín hiệu thay đổi.
 */
data class SnapshotEntry(
    val packageName: String,
    val label: String,
    val versionCode: Long,
    val fingerprints: Set<String>,
    val historyFingerprints: Set<String>,
    val market: MarketSignals?,
    val scannedAt: Long,
)

/** Lịch sử của một package qua các lần quét. */
data class PackageHistory(
    val packageName: String,
    /** Các bản ghi theo thứ tự thời gian; bản đầu tiên là mốc gốc (baseline). */
    val entries: List<SnapshotEntry>,
    /** Số lần quét đã thấy package này (kể cả các lần không có thay đổi). */
    val scanCount: Int,
    val firstSeen: Long,
    val lastSeen: Long,
)

/** Một lần thay đổi của một tín hiệu giữa hai bản ghi liên tiếp. */
data class SignalChange(
    val signal: String,
    val from: String,
    val to: String,
    val at: Long,
)

enum class ConfidenceLevel(val label: String) {
    CLEAR("Tín hiệu đầy đủ, ổn định"),
    AMBIGUOUS("Thiếu hoặc biến động một phần"),
    UNCLEAR("Thiếu hoặc biến động nghiêm trọng"),
}

data class AppReport(
    val signals: AppSignals,
    val findings: List<Finding>,
    val history: List<SnapshotEntry>,
    val changes: List<SignalChange>,
    val score: Int,
    val level: ConfidenceLevel,
) {
    val highCount: Int get() = findings.count { it.severity == Severity.HIGH }
    val mediumCount: Int get() = findings.count { it.severity == Severity.MEDIUM }
}
