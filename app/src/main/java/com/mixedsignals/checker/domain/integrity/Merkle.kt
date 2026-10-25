package com.mixedsignals.checker.domain.integrity

import java.security.MessageDigest

/**
 * Cây Merkle theo RFC 6962 (dùng bởi transparency log của Google, định dạng C2SP tlog-tiles).
 *  - lá:   SHA-256(0x00 || dữ liệu)
 *  - nút:  SHA-256(0x01 || trái || phải)
 */
object Merkle {
    private fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach { md.update(it) }
        return md.digest()
    }

    fun leafHash(data: ByteArray): ByteArray = sha256(byteArrayOf(0), data)
    fun nodeHash(l: ByteArray, r: ByteArray): ByteArray = sha256(byteArrayOf(1), l, r)

    /** Lũy thừa của 2 lớn nhất NHỎ HƠN n (n ≥ 2). */
    fun splitPoint(n: Long): Long {
        var k = 1L
        while (k shl 1 < n) k = k shl 1
        return k
    }

    /**
     * Nguồn hash đã lưu: hash của cây con hoàn chỉnh ở [level] (0 = lá), chỉ số [index]
     * (bao các lá [index·2^level, (index+1)·2^level)).
     */
    fun interface StoredHashes {
        fun get(level: Int, index: Long): ByteArray
    }

    /**
     * Tính gốc của cây kích thước [treeSize], trong đó lá ở vị trí [leafIndex] được thay bằng [leafHash]
     * của chính mình, còn mọi cây con khác lấy từ [stored]. Nếu kết quả bằng gốc trong checkpoint đã ký
     * thì bản ghi chắc chắn nằm trong log (tương đương kiểm inclusion proof).
     */
    fun rootWithLeaf(treeSize: Long, leafIndex: Long, leafHash: ByteArray, stored: StoredHashes): ByteArray {
        require(leafIndex in 0 until treeSize) { "leafIndex ngoài phạm vi" }
        return subtree(0, treeSize, leafIndex, leafHash, stored)
    }

    private fun subtree(lo: Long, hi: Long, leafIndex: Long, leafHash: ByteArray, stored: StoredHashes): ByteArray {
        val n = hi - lo
        if (n == 1L) return if (lo == leafIndex) leafHash else stored.get(0, lo)
        val containsLeaf = leafIndex in lo until hi
        // Cây con hoàn chỉnh, căn lề, không chứa lá đang kiểm: lấy thẳng hash đã lưu.
        if (!containsLeaf && n and (n - 1) == 0L && lo % n == 0L) {
            return stored.get(java.lang.Long.numberOfTrailingZeros(n), lo / n)
        }
        val k = if (n and (n - 1) == 0L) n / 2 else splitPoint(n)
        return nodeHash(
            subtree(lo, lo + k, leafIndex, leafHash, stored),
            subtree(lo + k, hi, leafIndex, leafHash, stored),
        )
    }

    /** Gốc Merkle của danh sách lá (dùng để kiểm thử). */
    fun rootOf(leaves: List<ByteArray>): ByteArray {
        val hashes = leaves.map { leafHash(it) }
        fun mth(lo: Int, hi: Int): ByteArray {
            if (hi - lo == 1) return hashes[lo]
            val k = splitPoint((hi - lo).toLong()).toInt()
            return nodeHash(mth(lo, lo + k), mth(lo + k, hi))
        }
        return mth(0, hashes.size)
    }
}
