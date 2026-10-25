package com.mixedsignals.checker.domain

import com.mixedsignals.checker.domain.model.CertInfo
import com.mixedsignals.checker.domain.text.Normalizer

/** Loại chứng chỉ nhận diện được từ subject (§2.1, §5.1, §5.2). */
enum class CertKind(val label: String) {
    /** Khóa debug do Android SDK tự sinh: CN=Android Debug. */
    DEBUG("Chứng chỉ debug"),
    /** Khóa test công khai của AOSP (testkey/platform/shared/media): private key đã công khai. */
    AOSP_TEST("Khóa test công khai của AOSP"),
    /** Subject đúng mẫu Google: Play App Signing hoặc khóa của chính Google. */
    GOOGLE_PATTERN("Mẫu Google / Play App Signing"),
    /** Có chữ "Google" nhưng không đúng mẫu chuẩn. */
    GOOGLE_LOOKALIKE("Giống Google nhưng sai mẫu"),
    /** CN/O mang giá trị vô nghĩa như "Android", "Unknown", "Company". */
    GENERIC("Subject chung chung"),
    NORMAL("Bình thường"),
}

object CertClassifier {
    /** Giá trị CN / O không mang thông tin tác giả. */
    val GENERIC_SUBJECT_VALUES = setOf(
        "android", "unknown", "company", "test", "debug", "default", "name", "organization",
        "organisation", "me", "admin", "n a", "na", "none", "xxx", "abc", "developer", "my company",
        "your company", "app", "apps", "mobile", "release", "key", "key0", "a", "aa",
    )

    fun classify(c: CertInfo): CertKind {
        val s = c.subject
        val cn = s["CN"].orEmpty()
        val o = s["O"].orEmpty()
        if (cn.equals("Android Debug", ignoreCase = true)) return CertKind.DEBUG
        if (s["EMAILADDRESS"].equals("android@android.com", ignoreCase = true) &&
            o.equals("Android", ignoreCase = true)
        ) return CertKind.AOSP_TEST
        if (isGooglePattern(s)) return CertKind.GOOGLE_PATTERN
        if (s.values.any { it.contains("google", ignoreCase = true) }) return CertKind.GOOGLE_LOOKALIKE
        val nCn = Normalizer.basic(cn)
        val nO = Normalizer.basic(o)
        val cnGeneric = nCn.isEmpty() || nCn in GENERIC_SUBJECT_VALUES
        val oGeneric = nO.isEmpty() || nO in GENERIC_SUBJECT_VALUES
        if (cnGeneric && oGeneric) return CertKind.GENERIC
        return CertKind.NORMAL
    }

    /**
     * Mẫu subject của chứng chỉ Google: CN=Android, OU=Android, O=Google Inc. (hoặc Google LLC),
     * L=Mountain View, ST=California, C=US. Mẫu này dùng cho cả Play App Signing lẫn app của chính Google,
     * nên chỉ nhìn subject thì không phân biệt được hai trường hợp (paper §5.2).
     */
    fun isGooglePattern(s: Map<String, String>): Boolean =
        s["CN"].equals("Android", true) &&
            s["OU"].equals("Android", true) &&
            (s["O"].equals("Google Inc.", true) || s["O"].equals("Google LLC", true) || s["O"].equals("Google Inc", true)) &&
            s["L"].equals("Mountain View", true) &&
            s["ST"].equals("California", true) &&
            s["C"].equals("US", true)
}
