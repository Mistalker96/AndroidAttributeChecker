package com.mixedsignals.checker

import com.mixedsignals.checker.domain.integrity.ApkEvidence
import com.mixedsignals.checker.domain.integrity.CheckStatus
import com.mixedsignals.checker.domain.integrity.CodeTransparency
import com.mixedsignals.checker.domain.integrity.CodeTransparencyResult
import com.mixedsignals.checker.domain.integrity.Impersonation
import com.mixedsignals.checker.domain.integrity.IntegrityAnalyzer
import com.mixedsignals.checker.domain.integrity.IntegrityInput
import com.mixedsignals.checker.domain.integrity.IntegrityVerdict
import com.mixedsignals.checker.domain.integrity.KeySibling
import com.mixedsignals.checker.domain.integrity.LogCheckResult
import com.mixedsignals.checker.domain.integrity.Merkle
import com.mixedsignals.checker.domain.integrity.PermissionCatalog
import com.mixedsignals.checker.domain.integrity.ProtectedComponent
import com.mixedsignals.checker.domain.integrity.ReproResult
import com.mixedsignals.checker.domain.integrity.RiskTier
import com.mixedsignals.checker.domain.integrity.SharedKeys
import com.mixedsignals.checker.domain.integrity.SignedNote
import com.mixedsignals.checker.domain.integrity.SourceParsers
import com.mixedsignals.checker.domain.integrity.SourceResult
import com.mixedsignals.checker.domain.model.CertInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import java.util.Date

class IntegrityTest {

    // ================================================================ Merkle / log

    @Test fun merkleRootWithLeafMatchesNaiveRootForManySizes() {
        for (n in listOf(1, 2, 3, 5, 8, 13, 31, 64, 100, 257, 600)) {
            val leaves = (0 until n).map { "entry-$it".toByteArray() }
            val expected = Merkle.rootOf(leaves)
            val stored = Merkle.StoredHashes { level, index ->
                val size = 1 shl level
                Merkle.rootOf(leaves.subList((index * size).toInt(), ((index + 1) * size).toInt()))
            }
            for (i in listOf(0, n / 2, n - 1)) {
                val root = Merkle.rootWithLeaf(n.toLong(), i.toLong(), Merkle.leafHash(leaves[i]), stored)
                assertArrayEquals("n=$n i=$i", expected, root)
                // Lá sai thì gốc phải khác.
                assertFalse(Merkle.rootWithLeaf(n.toLong(), i.toLong(), Merkle.leafHash("x".toByteArray()), stored).contentEquals(expected))
            }
        }
    }

    // Checkpoint thật tải từ log Google (phần nội dung + chữ ký của chính log).
    private val realCheckpoint = "android.transparency.goog/google1p/apk/2026/1\n783370\nTdU8KXP/WzXEA9TEv7s9xFxSFItFWXmp0EZv5MqFJSg=\n\n" +
        "— android.transparency.goog/google1p/apk/2026/1 /GVDdNe/AEAyarUDYBZEGhPlkKgAYZlMhe1q//OamnkbHZnEUXq7Axq5Q7LrDjxkRj32JJZe2dgaEmV23f2o7JIDjg0=\n"
    private val key = "android.transparency.goog/google1p/apk/2026/1+fc654374+ATr9NQE0gvOtVfj5cCStUzdlflEp3oZoNHD8pImzPj5O"

    @Test fun verifiesRealGoogleCheckpoint() {
        val cp = SignedNote.verifyCheckpoint(realCheckpoint, key)
        assertEquals(783370L, cp.size)
        assertEquals(32, cp.rootHash.size)
    }

    @Test fun rejectsTamperedCheckpoint() {
        try {
            SignedNote.verifyCheckpoint(realCheckpoint.replace("783370", "783371"), key)
            fail("phải từ chối checkpoint bị sửa")
        } catch (e: SignedNote.InvalidNote) {
            assertTrue(e.message!!.contains("không hợp lệ"))
        }
    }

    @Test fun tilePathsAndEntryBundles() {
        assertEquals("005", SourceParsers.tileIndexPath(5))
        assertEquals("x003/059", SourceParsers.tileIndexPath(3059))
        assertEquals("x001/x234/067", SourceParsers.tileIndexPath(1234067))
        val a = "abc".toByteArray(); val b = ByteArray(300) { 7 }
        val bundle = byteArrayOf(0, 3) + a + byteArrayOf(1, 44) + b
        val parsed = SourceParsers.parseEntryBundle(bundle)
        assertEquals(2, parsed.size)
        assertArrayEquals(b, parsed[1])
        assertEquals("ab\nSHA256(APK)\ncom.x\n7\n", SourceParsers.googleApkPayload("AB", "com.x", 7))
    }

    // ================================================================ nguồn công bố

    private val fpA = "a".repeat(64)
    private val fpB = "b".repeat(64)

    @Test fun parsesUserFingerprintsInBothFormats() {
        val colon = fpA.chunked(2).joinToString(":").uppercase()
        assertEquals(setOf(fpA, fpB), SourceParsers.parseUserFingerprints("SHA-256: $colon\n$fpB"))
        assertTrue(SourceParsers.parseUserFingerprints("không có").isEmpty())
    }

    @Test fun parsesAssetLinks() {
        val json = """[{"relation":["delegate_permission/common.handle_all_urls"],
            "target":{"namespace":"android_app","package_name":"com.acme","sha256_cert_fingerprints":["${fpA.chunked(2).joinToString(":").uppercase()}"]}},
            {"target":{"namespace":"web","site":"https://acme.com"}}]"""
        assertEquals(setOf(fpA), SourceParsers.assetLinksFingerprints(json, "com.acme"))
        assertTrue(SourceParsers.assetLinksFingerprints(json, "com.other").isEmpty())
    }

    @Test fun parsesFdroidAndIzzy() {
        assertEquals(fpA, SourceParsers.fdroidSigner("""{"com.acme":{"signer":"$fpA"}}""", "com.acme"))
        val rep = """{"1.0":{"local":{"sha256":"x"},"remote":{"sha256":"$fpB"},"verified":true},"2.0":{"verified":false}}"""
        val v = SourceParsers.fdroidVerification(rep)
        assertTrue(v.any { it.verified && it.publishedSha256 == fpB })
        val izzy = """{"$fpA":[{"appid":"com.acme","version_code":3,"reproducible":true,"repository":"https://github.com/acme/app.git"}]}"""
        assertEquals(true, SourceParsers.izzyLookup(izzy, fpA).single().reproducible)
        assertTrue(SourceParsers.izzyLookup(izzy, fpB).isEmpty())
    }

    // ================================================================ Code Transparency

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun b64u(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    /** Tạo JWS RS256 giống bundletool, trả về (jws, fingerprint khóa). */
    private fun makeJws(dexSha: String, soSha: String): Pair<String, String> {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        val name = X500Name("CN=Code Transparency Test")
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.ONE, Date(0), Date(4102444800000), name, kp.public)
            .build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private))
        val cert = JcaX509CertificateConverter().getCertificate(holder)
        val header = """{"alg":"RS256","x5c":["${Base64.getEncoder().encodeToString(cert.encoded)}"]}"""
        val payload = """{"codeRelatedFile":[{"path":"base/dex/classes.dex","type":"DEX","sha256":"$dexSha"},
            {"path":"base/lib/arm64-v8a/libx.so","type":"NATIVE_LIBRARY","apkPath":"lib/arm64-v8a/libx.so","sha256":"$soSha"}],"version":1}"""
        val input = b64u(header.toByteArray()) + "." + b64u(payload.toByteArray())
        val sig = Signature.getInstance("SHA256withRSA").run { initSign(kp.private); update(input.toByteArray()); sign() }
        return "$input.${b64u(sig)}" to sha(cert.encoded)
    }

    @Test fun codeTransparencyPassesAndAnchors() {
        val dex = sha("dex".toByteArray()); val so = sha("so".toByteArray())
        val (jws, keyFp) = makeJws(dex, so)
        val entries = mapOf("base.apk" to mapOf("classes.dex" to dex, "lib/arm64-v8a/libx.so" to so))
        val notAnchored = CodeTransparency.verify(jws, entries, false, emptySet(), null, emptySet())
        assertEquals(CheckStatus.PASS, notAnchored.status)
        assertFalse(notAnchored.keyAnchored)
        assertEquals(keyFp, notAnchored.keyFingerprint)
        val anchored = CodeTransparency.verify(jws, entries, false, setOf(keyFp.uppercase()), null, emptySet())
        assertTrue(anchored.keyAnchored)
        assertEquals(2, anchored.checkedFiles)
    }

    @Test fun codeTransparencyDetectsModifiedCodeAndWrongKey() {
        val dex = sha("dex".toByteArray()); val so = sha("so".toByteArray())
        val (jws, _) = makeJws(dex, so)
        val tampered = mapOf("base.apk" to mapOf("classes.dex" to sha("evil".toByteArray()), "lib/arm64-v8a/libx.so" to so))
        assertEquals(CheckStatus.FAIL, CodeTransparency.verify(jws, tampered, false, emptySet(), null, emptySet()).status)
        val ok = mapOf("base.apk" to mapOf("classes.dex" to dex))
        assertEquals(CheckStatus.FAIL, CodeTransparency.verify(jws, ok, false, setOf(fpA), null, emptySet()).status)
        assertEquals(CheckStatus.FAIL, CodeTransparency.verify(jws, ok, false, emptySet(), fpB, emptySet()).status)
        // Thư viện native nằm ở split vắng mặt: vẫn đạt nhưng báo thiếu.
        val partial = CodeTransparency.verify(jws, ok, false, emptySet(), null, emptySet())
        assertEquals(CheckStatus.PASS, partial.status)
        assertEquals(1, partial.missingFiles)
        // Chữ ký JWS bị sửa.
        val badSig = jws.substring(0, jws.lastIndexOf('.') + 1) + b64u(ByteArray(384))
        assertEquals(CheckStatus.FAIL, CodeTransparency.verify(badSig, ok, false, emptySet(), null, emptySet()).status)
        assertEquals(CheckStatus.NA, CodeTransparency.verify(null, ok, false, emptySet(), null, emptySet()).status)
    }

    // ================================================================ quyền, mạo danh, khóa dùng chung

    private fun cert(fp: String, vararg rdn: Pair<String, String>) = CertInfo(
        fp, mapOf(*rdn), mapOf(*rdn), true, 0, Long.MAX_VALUE, "SHA256withRSA", "RSA", 2048,
    )
    private val goodCert = cert(fpA, "CN" to "Acme", "O" to "Acme Ltd", "OU" to "Mobile", "L" to "Hanoi", "ST" to "Hanoi", "C" to "VN")

    private fun apk(
        pkg: String = "com.acme.app", label: String = "Acme Notes", perms: List<String> = listOf("android.permission.INTERNET"),
        comps: List<ProtectedComponent> = emptyList(), verified: Boolean = true, certs: List<CertInfo> = listOf(goodCert),
        debuggable: Boolean = false, targetSdk: Int = 34, stamp: Boolean = false,
    ) = ApkEvidence(
        "a.apk", fpB, 1, pkg, label, "1.0", 1, 28, targetSdk, debuggable, false, perms, comps,
        verified, emptyList(), setOf(2, 3), certs, emptyList(), stamp, stamp,
    )

    @Test fun permissionTiers() {
        assertEquals(RiskTier.GREEN, PermissionCatalog.assess(apk()).overall)
        assertEquals(RiskTier.YELLOW, PermissionCatalog.assess(apk(perms = listOf("android.permission.CAMERA"))).overall)
        assertEquals(RiskTier.RED, PermissionCatalog.assess(apk(perms = listOf("android.permission.READ_SMS"))).overall)
        // Quyền nguy hiểm nhất nằm ở service: Accessibility, đọc thông báo.
        val acc = PermissionCatalog.assess(apk(comps = listOf(ProtectedComponent("com.acme.Svc", "android.permission.BIND_ACCESSIBILITY_SERVICE"))))
        assertEquals(RiskTier.RED, acc.overall)
        assertEquals("com.acme.Svc", acc.byTier(RiskTier.RED).single().viaComponent)
        // Gửi thông báo là xanh; targetSdk cũ là đỏ.
        assertEquals(RiskTier.GREEN, PermissionCatalog.assess(apk(perms = listOf("android.permission.POST_NOTIFICATIONS"))).overall)
        assertEquals(RiskTier.RED, PermissionCatalog.assess(apk(targetSdk = 22)).overall)
        assertEquals(RiskTier.GREEN, PermissionCatalog.lookup("com.acme.app.permission.C2D_MESSAGE", "com.acme.app").tier)
        // Quyền hệ thống tự thêm (Android 17 thêm ACCESS_LOCAL_NETWORK từ INTERNET) không làm tăng mức rủi ro.
        val implicit = apk(perms = listOf("android.permission.INTERNET", "android.permission.ACCESS_LOCAL_NETWORK"))
            .copy(implicitPermissions = setOf("android.permission.ACCESS_LOCAL_NETWORK"))
        assertEquals(RiskTier.GREEN, PermissionCatalog.assess(implicit).overall)
    }

    @Test fun impersonation() {
        assertTrue(Impersonation.detect("Facebook Lite Pro", "com.fb.free").suspected)
        assertTrue(Impersonation.detect("Zal0", "com.zalo.fake").suspected)
        assertFalse(Impersonation.detect("Zalo", "com.zing.zalo").suspected)
        assertFalse(Impersonation.detect("Calculator", "com.acme.calc").suspected)
        assertFalse(Impersonation.detect("Acme Notes", "com.acme.app").suspected)
    }

    @Test fun sharedKeysAndBuilders() {
        val andromo = SharedKeys.assess("com.andromo.dev271569.app366038", listOf(goodCert), emptyList())
        assertEquals("Andromo", andromo.builder?.name)
        val bySubject = SharedKeys.assess("com.radio.x", listOf(cert(fpA, "CN" to "Andromo App", "O" to "Andromo")), emptyList())
        assertEquals("Andromo", bySubject.builder?.name)
        val siblings = listOf(KeySibling("com.acme.other", "Acme 2"), KeySibling("org.stranger.app", "Stranger"))
        val r = SharedKeys.assess("com.acme.app", listOf(goodCert), siblings)
        assertEquals(listOf("org.stranger.app"), r.foreignSiblings.map { it.packageName })
        assertEquals(1, r.ownSiblings.size)
        assertTrue(r.detected)
        assertFalse(SharedKeys.assess("com.acme.app", listOf(goodCert), emptyList()).detected)
        // Google ký Chrome và Gmail bằng cùng khóa: cùng hãng, không phải khóa dùng chung đáng ngờ.
        val google = SharedKeys.assess("com.android.chrome", listOf(goodCert), listOf(KeySibling("com.google.android.gm", "Gmail")))
        assertFalse(google.detected)
        // Khóa Samsung dùng cho app của LogMeIn (ví dụ trong paper §7.2) vẫn bị phát hiện.
        assertTrue(SharedKeys.assess("com.sec.android.app.x", listOf(goodCert), listOf(KeySibling("com.logmein.rescue", "LogMeIn"))).detected)
        assertFalse(SharedKeys.assess("com.acme.app", listOf(goodCert), null).deviceScanned)
    }

    // ================================================================ 5 mức kết luận

    private val noCt = CodeTransparencyResult(CheckStatus.NA, "")
    private val noLog = LogCheckResult(CheckStatus.NA, "")
    private fun pass(name: String, publication: Boolean = true) = SourceResult(name, CheckStatus.PASS, setOf(fpA), publication = publication)

    private fun verdict(
        a: ApkEvidence = apk(), sources: List<SourceResult> = emptyList(), log: LogCheckResult = noLog,
        repro: List<ReproResult> = emptyList(), ct: CodeTransparencyResult = noCt,
        shared: com.mixedsignals.checker.domain.integrity.SharedKeyResult = SharedKeys.assess(a.packageName, a.signerCerts, emptyList()),
    ) = IntegrityAnalyzer.analyze(IntegrityInput(a, sources, ct, log, repro, null, null, shared)).verdict

    @Test fun verdictLevels() {
        assertEquals(IntegrityVerdict.TAMPERED, verdict(apk(verified = false)))
        assertEquals(IntegrityVerdict.TAMPERED, verdict(sources = listOf(SourceResult("Website", CheckStatus.FAIL, setOf(fpB)))))
        assertEquals(IntegrityVerdict.TAMPERED, verdict(log = LogCheckResult(CheckStatus.FAIL, "hash khác")))
        assertEquals(IntegrityVerdict.HIGH_RISK, verdict(apk(certs = listOf(cert(fpA, "CN" to "Android Debug", "O" to "Android", "C" to "US")))))
        assertEquals(IntegrityVerdict.HIGH_RISK, verdict(apk(label = "Facebook", pkg = "com.fake.fb"), sources = listOf(pass("Website"))))
        assertEquals(IntegrityVerdict.NO_DATA, verdict())
        assertEquals(IntegrityVerdict.LOW_RISK, verdict(apk(stamp = true)))
        assertEquals(IntegrityVerdict.LOW_RISK, verdict(sources = listOf(pass("Website"))))
        assertEquals(IntegrityVerdict.VERIFIED, verdict(sources = listOf(pass("Website"), pass("Digital Asset Links"))))
        assertEquals(IntegrityVerdict.VERIFIED, verdict(log = LogCheckResult(CheckStatus.PASS, "ok")))
        assertEquals(IntegrityVerdict.VERIFIED, verdict(sources = listOf(pass("Website")), repro = listOf(ReproResult("Izzy", CheckStatus.PASS, "ok"))))
        // Lịch sử trên máy không phải nguồn công bố.
        assertEquals(IntegrityVerdict.LOW_RISK, verdict(sources = listOf(pass("Website"), pass("Lần trước", publication = false))))
        // F-Droid khác khóa (không chính thức) không làm app bị coi là bị sửa.
        assertEquals(IntegrityVerdict.LOW_RISK, verdict(sources = listOf(pass("Website"), SourceResult("F-Droid", CheckStatus.FAIL, setOf(fpB), authoritative = false))))
    }

    @Test fun sharedKeyCapsVerifiedUnlessFileLevelEvidence() {
        val a = apk()
        val shared = SharedKeys.assess(a.packageName, a.signerCerts, listOf(KeySibling("org.stranger.app", "Stranger")))
        assertEquals(IntegrityVerdict.LOW_RISK, verdict(a, sources = listOf(pass("Website"), pass("Digital Asset Links")), shared = shared))
        assertEquals(IntegrityVerdict.VERIFIED, verdict(a, sources = listOf(pass("Website")), log = LogCheckResult(CheckStatus.PASS, "ok"), shared = shared))
    }

    @Test fun scoringCriteria() {
        fun report(a: ApkEvidence = apk(), sources: List<SourceResult> = emptyList()) =
            IntegrityAnalyzer.analyze(IntegrityInput(a, sources, noCt, noLog, emptyList(), null, null))
        // Fingerprint + checksum: 20 + 25 + 10 + 10 + 0 + 15 + 2 = 82.
        val verified = report(sources = listOf(pass("Website"), pass("Checksum")))
        assertEquals(IntegrityVerdict.VERIFIED, verified.verdict)
        assertEquals(82, verified.score.total)
        assertEquals(100, verified.score.items.sumOf { it.max })
        // Chữ ký hỏng → trần 10 điểm.
        val tampered = report(apk(verified = false))
        assertTrue(tampered.score.total <= 10)
        assertTrue(tampered.score.capNote != null)
        // Khóa debug → rủi ro cao, trần 45.
        assertTrue(report(apk(certs = listOf(cert(fpA, "CN" to "Android Debug", "O" to "Android", "C" to "US")))).score.total <= 45)
        // Điểm rủi ro quyền: 1 đỏ (30) + 1 vàng (10) = 40; tối đa 100.
        assertEquals(40, PermissionCatalog.assess(apk(perms = listOf("android.permission.READ_SMS", "android.permission.CAMERA"))).score)
        assertEquals(0, PermissionCatalog.assess(apk()).score)
        assertEquals(100, PermissionCatalog.assess(apk(perms = (1..5).map { listOf("READ_SMS", "SEND_SMS", "READ_CONTACTS", "CALL_PHONE", "READ_CALL_LOG")[it - 1] }.map { "android.permission.$it" })).score)
    }

    @Test fun baselineListsMissingItems() {
        val r = IntegrityAnalyzer.analyze(IntegrityInput(apk(), emptyList(), noCt, noLog, emptyList(), null, null))
        val missing = r.missingBaseline.map { it.title }
        assertTrue(missing.contains("Code Transparency"))
        // Chưa có metadata thì là "chưa biết", không phải "thiếu".
        assertFalse(missing.contains("URL privacy policy"))
        assertEquals(null, r.baseline.first { it.title == "URL privacy policy" }.present)
        val withMarket = IntegrityAnalyzer.analyze(
            IntegrityInput(apk(), emptyList(), noCt, noLog, emptyList(), com.mixedsignals.checker.domain.model.MarketSignals(developerName = "Acme", source = "play"), null),
        )
        assertTrue(withMarket.missingBaseline.any { it.title == "URL privacy policy" })
        assertFalse(missing.contains("Đủ 6 trường subject (CN, O, OU, L, ST, C)"))
    }
}
