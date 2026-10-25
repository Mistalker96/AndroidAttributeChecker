package com.mixedsignals.checker.domain.integrity

import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.security.MessageDigest
import java.util.Base64

/** Checkpoint của transparency log (định dạng C2SP signed note). */
data class Checkpoint(val origin: String, val size: Long, val rootHash: ByteArray)

/**
 * Xác minh "signed note" (C2SP) bằng khóa Ed25519.
 * Khóa verifier có dạng `<tên>+<hash 4 byte hex>+<base64(0x01 || khóa công khai 32 byte)>`.
 * Mỗi dòng chữ ký: `— <tên> <base64(hash 4 byte || chữ ký 64 byte)>`.
 */
object SignedNote {
    class InvalidNote(msg: String) : Exception(msg)

    fun verifyCheckpoint(note: String, verifierKey: String): Checkpoint {
        val parts = verifierKey.split('+')
        if (parts.size != 3) throw InvalidNote("Khóa verifier sai định dạng")
        val (name, hashHex, keyB64) = parts
        val key = Base64.getDecoder().decode(keyB64)
        if (key.size != 33 || key[0].toInt() != 1) throw InvalidNote("Chỉ hỗ trợ khóa Ed25519")
        val expectedHash = MessageDigest.getInstance("SHA-256")
            .digest(name.toByteArray() + byteArrayOf('\n'.code.toByte()) + key).copyOf(4)
        if (expectedHash.joinToString("") { "%02x".format(it) } != hashHex.lowercase()) throw InvalidNote("Hash của khóa không khớp")

        val sep = note.indexOf("\n\n")
        if (sep < 0) throw InvalidNote("Checkpoint không có phần chữ ký")
        val body = note.substring(0, sep + 1) // gồm ký tự xuống dòng cuối của phần nội dung
        val sigLines = note.substring(sep + 2).lines().filter { it.startsWith("— ") }
        val pub = key.copyOfRange(1, 33)
        val verified = sigLines.any { line ->
            val fields = line.removePrefix("— ").split(' ')
            if (fields.size != 2 || fields[0] != name) return@any false
            val sig = runCatching { Base64.getDecoder().decode(fields[1]) }.getOrNull() ?: return@any false
            sig.size == 68 && sig.copyOf(4).contentEquals(expectedHash) &&
                Ed25519.verify(sig, 4, pub, 0, body.toByteArray(), 0, body.toByteArray().size)
        }
        if (!verified) throw InvalidNote("Chữ ký của log không hợp lệ")

        val lines = body.trimEnd('\n').lines()
        if (lines.size < 3) throw InvalidNote("Checkpoint thiếu dòng")
        if (lines[0] != name) throw InvalidNote("Origin của checkpoint không khớp khóa")
        val size = lines[1].toLongOrNull() ?: throw InvalidNote("Kích thước cây sai định dạng")
        val root = Base64.getDecoder().decode(lines[2])
        if (root.size != 32) throw InvalidNote("Hash gốc sai độ dài")
        return Checkpoint(lines[0], size, root)
    }
}
