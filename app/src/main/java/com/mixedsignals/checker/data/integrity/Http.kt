package com.mixedsignals.checker.data.integrity

import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/** HTTP GET tối giản, có bộ nhớ đệm trên đĩa. */
object Http {
    class NotFound(url: String) : Exception("Không tìm thấy (404): $url")

    fun get(url: String, timeoutMs: Int = 20_000): ByteArray {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "AttributionChecker/2.0 (Android integrity checker)")
        try {
            val code = conn.responseCode
            if (code == 404 || code == 410) throw NotFound(url)
            if (code !in 200..299) error("HTTP $code: $url")
            return conn.inputStream.use { it.readBytes() }
        } finally {
            conn.disconnect()
        }
    }

    fun postJson(url: String, body: String, timeoutMs: Int = 20_000): ByteArray {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("User-Agent", "AttributionChecker/2.0 (Android integrity checker)")
        try {
            conn.outputStream.use { it.write(body.toByteArray()) }
            val code = conn.responseCode
            if (code == 404) throw NotFound(url)
            if (code !in 200..299) error("HTTP $code: $url")
            return conn.inputStream.use { it.readBytes() }
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Lấy từ cache nếu còn hạn ([maxAgeMs] < 0 nghĩa là không bao giờ hết hạn), ngược lại tải mới và lưu lại.
     * Nếu tải lỗi mà vẫn còn bản cũ thì dùng bản cũ.
     */
    fun cached(url: String, file: File, maxAgeMs: Long, timeoutMs: Int = 30_000): ByteArray {
        if (file.exists() && (maxAgeMs < 0 || System.currentTimeMillis() - file.lastModified() < maxAgeMs)) {
            return file.readBytes()
        }
        return try {
            val b = get(url, timeoutMs)
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeBytes(b)
            if (!tmp.renameTo(file)) { file.delete(); tmp.renameTo(file) }
            b
        } catch (e: NotFound) {
            throw e
        } catch (e: Exception) {
            if (file.exists()) file.readBytes() else throw e
        }
    }
}
