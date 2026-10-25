package com.mixedsignals.checker.domain.text

import java.text.Normalizer as JNormalizer

/** Chuẩn hóa chuỗi để so sánh giá trị tín hiệu giữa các lần quét. */
object Normalizer {
    /** Chữ thường, bỏ dấu, bỏ ký tự đặc biệt, gộp khoảng trắng. */
    fun basic(s: String): String {
        val noAccent = JNormalizer.normalize(s.lowercase(), JNormalizer.Form.NFD)
            .replace(Regex("\\p{M}+"), "")
            .replace('đ', 'd')
        return noAccent.replace(Regex("[^\\p{L}\\p{N}]+"), " ").trim().replace(Regex("\\s+"), " ")
    }

    /**
     * Hai giá trị coi là giống nhau nếu khớp sau chuẩn hóa. Paper so khớp theo chữ thường (§6.1);
     * chuẩn hóa thêm dấu và ký tự đặc biệt giúp không đếm nhầm "Cube Apps, Ltd." -> "Cube Apps Ltd" là thay đổi.
     */
    fun same(a: String?, b: String?): Boolean {
        val x = a?.takeIf { it.isNotBlank() }?.let(::basic)
        val y = b?.takeIf { it.isNotBlank() }?.let(::basic)
        return x == y
    }
}
