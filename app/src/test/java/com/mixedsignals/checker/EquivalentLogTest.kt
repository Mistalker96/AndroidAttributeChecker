package com.mixedsignals.checker

import com.mixedsignals.checker.domain.integrity.ApkEvidence
import com.mixedsignals.checker.domain.integrity.CheckStatus
import com.mixedsignals.checker.domain.integrity.CodeTransparencyResult
import com.mixedsignals.checker.domain.integrity.IntegrityAnalyzer
import com.mixedsignals.checker.domain.integrity.IntegrityInput
import com.mixedsignals.checker.domain.integrity.IntegrityVerdict
import com.mixedsignals.checker.domain.integrity.LocalLog
import com.mixedsignals.checker.domain.integrity.LogCheckResult
import com.mixedsignals.checker.domain.integrity.Merkle
import com.mixedsignals.checker.domain.integrity.Rekor
import com.mixedsignals.checker.domain.integrity.SourceResult
import com.mixedsignals.checker.domain.model.CertInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Kiểm tra tương đương khi app không có trong log Google: Sigstore Rekor và nhật ký cục bộ. */
class EquivalentLogTest {
    private val entryJson = javaClass.classLoader!!.getResource("rekor_entry.json")!!.readText()
    private val artifactSha = "fbec44c273d9db180a6669467dd0ba2a281a78e502fc4b0ae2a3687236163570"

    // ================================================================ Rekor (bản ghi thật)

    @Test fun verifiesRealRekorEntry() {
        val e = Rekor.parseEntry(entryJson)
        assertEquals(artifactSha, e.dataHash)
        assertNull("bản ghi thật phải xác minh được", Rekor.verifyEntry(e, artifactSha))
    }

    @Test fun rejectsWrongHashAndTamperedProof() {
        val e = Rekor.parseEntry(entryJson)
        assertEquals("hash trong bản ghi khác hash file", Rekor.verifyEntry(e, "0".repeat(64)))
        val p = e.proof!!
        val tampered = e.copy(proof = p.copy(hashes = listOf(ByteArray(32)) + p.hashes.drop(1)))
        assertEquals("bằng chứng Merkle không khớp gốc", Rekor.verifyEntry(tampered, artifactSha))
        val badCheckpoint = e.copy(proof = p.copy(checkpoint = p.checkpoint.replace("\n4163431\n", "\n4163432\n")))
        assertFalse(Rekor.verifyEntry(badCheckpoint, artifactSha) == null)
    }

    @Test fun rfc9162InclusionMatchesMerkleRoot() {
        // So thuật toán kiểm audit path (RFC 9162) với cách tính gốc trực tiếp.
        for (n in listOf(1, 2, 7, 33, 100)) {
            val leaves = (0 until n).map { "x$it".toByteArray() }
            val root = Merkle.rootOf(leaves)
            for (i in listOf(0, n / 2, n - 1)) {
                val proof = auditPath(leaves.map { Merkle.leafHash(it) }, i)
                assertTrue("n=$n i=$i", Rekor.verifyInclusion(Merkle.leafHash(leaves[i]), i.toLong(), n.toLong(), proof, root))
                assertFalse(Rekor.verifyInclusion(Merkle.leafHash("y".toByteArray()), i.toLong(), n.toLong(), proof, root))
            }
        }
    }

    /** Audit path RFC 6962 (để kiểm thử). */
    private fun auditPath(h: List<ByteArray>, m: Int): List<ByteArray> {
        if (h.size <= 1) return emptyList()
        val k = Merkle.splitPoint(h.size.toLong()).toInt()
        fun mth(l: List<ByteArray>): ByteArray = if (l.size == 1) l[0] else {
            val kk = Merkle.splitPoint(l.size.toLong()).toInt(); Merkle.nodeHash(mth(l.subList(0, kk)), mth(l.subList(kk, l.size)))
        }
        return if (m < k) auditPath(h.subList(0, k), m) + mth(h.subList(k, h.size))
        else auditPath(h.subList(k, h.size), m - k) + mth(h.subList(0, k))
    }

    // ================================================================ nhật ký cục bộ

    private val keyA = setOf("a".repeat(64))

    @Test fun localLogDetectsSplitView() {
        val e1 = LocalLog.append(emptyList(), 1, "com.demo.notes", 1, "1".repeat(64), keyA)
        val log = listOf(e1)
        assertEquals(CheckStatus.PASS, LocalLog.check(log, "com.demo.notes", 1, "1".repeat(64), keyA).status)
        assertEquals(CheckStatus.PASS, LocalLog.check(log, "com.demo.notes", 2, "2".repeat(64), keyA).status)
        // Cùng package, cùng phiên bản, cùng khóa, khác nội dung → split-view.
        assertEquals(CheckStatus.FAIL, LocalLog.check(log, "com.demo.notes", 1, "2".repeat(64), keyA).status)
        // Khác khóa: không phải split-view của cùng developer (đã có kiểm tra khóa riêng).
        assertEquals(CheckStatus.PASS, LocalLog.check(log, "com.demo.notes", 1, "2".repeat(64), setOf("b".repeat(64))).status)
    }

    @Test fun localLogChainDetectsTampering() {
        var log = listOf(LocalLog.append(emptyList(), 1, "p", 1, "1".repeat(64), keyA))
        log = log + LocalLog.append(log, 2, "q", 1, "2".repeat(64), keyA)
        assertNull(LocalLog.firstBroken(log))
        val edited = listOf(log[0].copy(fileSha256 = "9".repeat(64)), log[1])
        assertEquals(1L, LocalLog.firstBroken(edited))
        assertEquals(CheckStatus.UNKNOWN, LocalLog.check(edited, "p", 1, "1".repeat(64), keyA).status)
    }

    // ================================================================ ảnh hưởng tới kết luận

    private val cert = CertInfo("a".repeat(64), mapOf("CN" to "Acme", "O" to "Acme", "OU" to "M", "L" to "H", "ST" to "H", "C" to "VN"),
        emptyMap(), true, 0, Long.MAX_VALUE, "SHA256withRSA", "RSA", 2048)
    private val apk = ApkEvidence("a.apk", "f".repeat(64), 1, "com.acme.app", "Acme", "1", 1, 28, 34, false, false,
        listOf("android.permission.INTERNET"), emptyList(), true, emptyList(), setOf(2), listOf(cert), emptyList(), false, false)
    private val na = LogCheckResult(CheckStatus.NA, "")
    private fun verdict(sources: List<SourceResult>, rekor: LogCheckResult = na, local: LogCheckResult = na) =
        IntegrityAnalyzer.analyze(IntegrityInput(apk, sources, CodeTransparencyResult(CheckStatus.NA, ""), na, emptyList(), null, null,
            rekor = rekor, localLog = local))

    @Test fun rekorIsIndependentEvidenceButNotIdentity() {
        val rekorPass = LogCheckResult(CheckStatus.PASS, "ok")
        val website = SourceResult("Website", CheckStatus.PASS, setOf("a".repeat(64)))
        // Khớp danh tính + có bản ghi Rekor → Toàn vẹn.
        assertEquals(IntegrityVerdict.VERIFIED, verdict(listOf(website), rekor = rekorPass).verdict)
        // Chỉ có Rekor (ai cũng ghi được) → chưa đủ để biết ai là tác giả.
        assertEquals(IntegrityVerdict.NO_DATA, verdict(emptyList(), rekor = rekorPass).verdict)
        val r = verdict(emptyList(), rekor = rekorPass)
        assertEquals(CheckStatus.PASS, r.checks.first { it.id == "TLOG" }.status)
    }

    @Test fun splitViewRaisesHighRisk() {
        val website = SourceResult("Website", CheckStatus.PASS, setOf("a".repeat(64)))
        val r = verdict(listOf(website), local = LogCheckResult(CheckStatus.FAIL, "split-view"))
        assertEquals(IntegrityVerdict.HIGH_RISK, r.verdict)
        assertTrue(r.checks.any { it.id == "LOCAL_LOG" && it.status == CheckStatus.FAIL })
    }
}
