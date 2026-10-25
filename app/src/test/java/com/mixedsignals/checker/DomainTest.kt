package com.mixedsignals.checker

import com.mixedsignals.checker.domain.Analyzer
import com.mixedsignals.checker.domain.AvailabilityChecks
import com.mixedsignals.checker.domain.CertChange
import com.mixedsignals.checker.domain.CertClassifier
import com.mixedsignals.checker.domain.CertKind
import com.mixedsignals.checker.domain.DeviceStats
import com.mixedsignals.checker.domain.MarkdownReport
import com.mixedsignals.checker.domain.VolatilityChecks
import com.mixedsignals.checker.domain.model.AppSignals
import com.mixedsignals.checker.domain.model.CertInfo
import com.mixedsignals.checker.domain.model.ConfidenceLevel
import com.mixedsignals.checker.domain.model.MarketSignals
import com.mixedsignals.checker.domain.model.Severity
import com.mixedsignals.checker.domain.text.Normalizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainTest {

    private fun cert(fp: String, vararg rdn: Pair<String, String>) = CertInfo(
        sha256 = fp, subject = mapOf(*rdn), issuer = mapOf(*rdn), selfSigned = true,
        notBefore = 0, notAfter = 1, sigAlg = "SHA256withRSA", keyAlg = "RSA", keySizeBits = 2048,
    )

    private val fullCert = cert(
        "aa", "CN" to "Jane Dev", "O" to "Acme Ltd", "OU" to "Mobile", "L" to "Hanoi", "ST" to "Hanoi", "C" to "VN",
    )

    private fun app(
        certs: List<CertInfo> = listOf(fullCert),
        history: List<CertInfo> = emptyList(),
        label: String = "Acme",
        market: MarketSignals? = null,
        schemes: Set<Int> = setOf(2, 3),
        at: Long = 1000,
    ) = AppSignals(
        packageName = "com.acme.app", manifestLabel = label, versionName = "1", versionCode = 1,
        installer = "com.android.vending", isSystemApp = false, fromFile = false, schemes = schemes,
        currentCerts = certs, certHistory = history, hasMultipleSigners = false, market = market, scannedAt = at,
    )

    private val fullMarket = MarketSignals(
        appName = "Acme", developerName = "Acme Ltd", website = "https://acme.vn", email = "a@acme.vn",
        address = "1 Street, Hanoi", privacyPolicyUrl = "https://acme.vn/privacy", source = "play",
    )

    // ---------- Độ sẵn có (§5.1) ----------

    @Test fun missingRdnSeverityGrowsWithCount() {
        val one = AvailabilityChecks.certFindings(app(certs = listOf(cert("x", "CN" to "A", "O" to "B", "OU" to "C", "L" to "D", "ST" to "E"))))
        assertEquals(Severity.LOW, one.first { it.id == "CERT_MISSING_RDN" }.severity)
        val three = AvailabilityChecks.certFindings(app(certs = listOf(cert("x", "CN" to "Jane", "O" to "Acme", "C" to "VN"))))
        assertEquals(Severity.MEDIUM, three.first { it.id == "CERT_MISSING_RDN" }.severity)
        val five = AvailabilityChecks.certFindings(app(certs = listOf(cert("x", "CN" to "Jane"))))
        assertEquals(Severity.HIGH, five.first { it.id == "CERT_MISSING_RDN" }.severity)
        val none = AvailabilityChecks.certFindings(app())
        assertTrue(none.none { it.id == "CERT_MISSING_RDN" })
    }

    @Test fun classifiesSpecialCertificates() {
        assertEquals(CertKind.DEBUG, CertClassifier.classify(cert("d", "CN" to "Android Debug", "O" to "Android", "C" to "US")))
        assertEquals(
            CertKind.AOSP_TEST,
            CertClassifier.classify(cert("t", "EMAILADDRESS" to "android@android.com", "CN" to "Android", "O" to "Android")),
        )
        val google = cert(
            "g", "CN" to "Android", "OU" to "Android", "O" to "Google Inc.", "L" to "Mountain View", "ST" to "California", "C" to "US",
        )
        assertEquals(CertKind.GOOGLE_PATTERN, CertClassifier.classify(google))
        // Ví dụ trong paper §5.2: O=Google, CN=Cupid.
        assertEquals(CertKind.GOOGLE_LOOKALIKE, CertClassifier.classify(cert("c", "CN" to "Cupid", "O" to "Google")))
        assertEquals(CertKind.GENERIC, CertClassifier.classify(cert("u", "CN" to "Unknown", "O" to "Unknown")))
        assertEquals(CertKind.NORMAL, CertClassifier.classify(fullCert))
    }

    @Test fun googleLookalikeIsOnlyInfoForSystemApps() {
        // Subject thật của YouTube trên máy ảo Google (quan sát khi chạy thử).
        val yt = cert(
            "y", "CN" to "Unknown", "OU" to "Google, Inc", "O" to "Google, Inc", "L" to "Mountain View", "ST" to "CA", "C" to "US",
        )
        assertEquals(CertKind.GOOGLE_LOOKALIKE, CertClassifier.classify(yt))
        val sys = AvailabilityChecks.certFindings(app(certs = listOf(yt)).copy(isSystemApp = true))
        assertEquals(Severity.INFO, sys.first { it.id == "CERT_GOOGLE_LOOKALIKE" }.severity)
        val user = AvailabilityChecks.certFindings(app(certs = listOf(yt)))
        assertEquals(Severity.MEDIUM, user.first { it.id == "CERT_GOOGLE_LOOKALIKE" }.severity)
    }

    @Test fun marketMissingFieldsOnlySevereWhenFromPlay() {
        val play = AvailabilityChecks.marketFindings(app(market = MarketSignals(developerName = "Acme", source = "play")))
        assertEquals(Severity.MEDIUM, play.first { it.id == "MARKET_MISSING_PRIVACY_POLICY" }.severity)
        assertEquals(Severity.LOW, play.first { it.id == "MARKET_MISSING_ADDRESS" }.severity)
        val manual = AvailabilityChecks.marketFindings(app(market = MarketSignals(developerName = "Acme", source = "manual")))
        assertTrue(manual.all { it.severity == Severity.INFO })
        val none = AvailabilityChecks.marketFindings(app())
        assertEquals(listOf("MARKET_NOT_COLLECTED"), none.map { it.id })
        assertTrue(AvailabilityChecks.marketFindings(app(market = fullMarket)).isEmpty())
    }

    @Test fun schemeFindings() {
        assertTrue(AvailabilityChecks.schemeFindings(app(schemes = setOf(1))).any { it.id == "SCHEME_V1_ONLY" })
        val multi = AvailabilityChecks.schemeFindings(app(schemes = setOf(1, 2, 3)))
        assertTrue(multi.any { it.id == "SCHEME_MULTI" } && multi.any { it.id == "SCHEME_V3" })
    }

    @Test fun completeAppScoresClear() {
        val s = app(market = fullMarket)
        val r = Analyzer.analyze(s, VolatilityChecks.updatedHistory(s, null))
        assertEquals(ConfidenceLevel.CLEAR, r.level)
        assertTrue(r.score >= 80)
    }

    @Test fun debugCertWithEmptySubjectScoresLow() {
        val s = app(certs = listOf(cert("d", "CN" to "Android Debug")), schemes = setOf(1))
        val r = Analyzer.analyze(s, null)
        assertEquals(ConfidenceLevel.UNCLEAR, r.level)
    }

    // ---------- Độ biến động (§5.2) ----------

    @Test fun historyAddsEntryOnlyWhenSignalsChange() {
        val h1 = VolatilityChecks.updatedHistory(app(at = 1), null)
        val h2 = VolatilityChecks.updatedHistory(app(at = 2), h1)
        assertEquals(1, h2.entries.size)
        assertEquals(2, h2.scanCount)
        val h3 = VolatilityChecks.updatedHistory(app(label = "Acme Pro", at = 3), h2)
        assertEquals(2, h3.entries.size)
        assertEquals(3, h3.scanCount)
    }

    @Test fun marketUpdateDoesNotCountAsScan() {
        val h1 = VolatilityChecks.updatedHistory(app(at = 1), null)
        val h2 = VolatilityChecks.updatedHistory(app(market = fullMarket, at = 2), h1, countAsScan = false)
        assertEquals(1, h2.scanCount)
        assertEquals(2, h2.entries.size)
    }

    @Test fun missingMarketInLaterScanKeepsPreviousMarket() {
        val h1 = VolatilityChecks.updatedHistory(app(market = fullMarket, at = 1), null)
        val h2 = VolatilityChecks.updatedHistory(app(market = null, at = 2), h1)
        assertEquals(1, h2.entries.size)
    }

    @Test fun certChangeKinds() {
        val a = VolatilityChecks.entryOf(app(certs = listOf(cert("a"))))
        val added = VolatilityChecks.entryOf(app(certs = listOf(cert("a"), cert("b"))))
        val replaced = VolatilityChecks.entryOf(app(certs = listOf(cert("z"))))
        val rotated = VolatilityChecks.entryOf(app(certs = listOf(cert("b")), history = listOf(cert("a"), cert("b"))))
        val partial = VolatilityChecks.entryOf(app(certs = listOf(cert("b"), cert("c"))))
        val start = VolatilityChecks.entryOf(app(certs = listOf(cert("a"), cert("b"))))
        assertEquals(CertChange.NONE, VolatilityChecks.certChange(a, a))
        assertEquals(CertChange.ADDED, VolatilityChecks.certChange(a, added))
        assertEquals(CertChange.REPLACED, VolatilityChecks.certChange(a, replaced))
        assertEquals(CertChange.ROTATED, VolatilityChecks.certChange(a, rotated))
        assertEquals(CertChange.PARTIAL, VolatilityChecks.certChange(start, partial))
    }

    @Test fun replacedCertificateIsHigh() {
        val h1 = VolatilityChecks.updatedHistory(app(certs = listOf(cert("a")), at = 1), null)
        val s2 = app(certs = listOf(cert("z")), at = 2)
        val h2 = VolatilityChecks.updatedHistory(s2, h1)
        val r = Analyzer.analyze(s2, h2)
        assertEquals(Severity.HIGH, r.findings.first { it.id == "CHANGED_CERT_REPLACED" }.severity)
    }

    @Test fun developerNameChangesCountedAndRevertDetected() {
        var h = VolatilityChecks.updatedHistory(app(market = fullMarket, at = 1), null)
        val names = listOf("Cube Apps", "Cube Apps Ltd 2", "Cube Studio", "Acme Ltd")
        names.forEachIndexed { i, n ->
            h = VolatilityChecks.updatedHistory(app(market = fullMarket.copy(developerName = n), at = 2L + i), h)
        }
        val findings = VolatilityChecks.run(h.entries)
        val dev = findings.first { it.id == "CHANGED_DEVELOPER_NAME" }
        // Giá trị cuối trùng giá trị đầu -> đổi rồi quay về.
        assertEquals(Severity.INFO, dev.severity)
        assertTrue(dev.title.contains("quay về"))
        assertEquals(4, VolatilityChecks.changes(h.entries).count { it.signal == "Tên developer" })
    }

    @Test fun revertDetectedWhenFirstScanHadNoMarket() {
        // Tái hiện trên máy ảo: quét (chưa có market) -> tra Play "Google LLC" -> sửa "Google Inc." -> tra lại.
        var h = VolatilityChecks.updatedHistory(app(at = 1), null)
        listOf("Google LLC", "Google Inc.", "Google LLC").forEachIndexed { i, n ->
            h = VolatilityChecks.updatedHistory(app(market = fullMarket.copy(developerName = n), at = 2L + i), h, countAsScan = false)
        }
        h = VolatilityChecks.updatedHistory(app(at = 9), h) // lần quét thứ 2
        assertEquals(setOf("Tên developer"), VolatilityChecks.revertedSignals(h.entries))
        val dev = VolatilityChecks.run(h.entries).first { it.id == "CHANGED_DEVELOPER_NAME" }
        assertEquals(Severity.INFO, dev.severity)
        val r = Analyzer.analyze(app(market = fullMarket.copy(developerName = "Google LLC"), at = 9), h)
        val stats = DeviceStats.compute(listOf(r), mapOf(r.signals.packageName to h))
        val vol = stats[3].rows
        assertEquals(1, vol.first { it.label == "Đổi rồi quay về giá trị cũ" }.count)
        assertEquals(0, vol.first { it.label == "Đổi tên developer" }.count)
        assertEquals(1, vol.first { it.label == "Đổi tên developer" }.total)
    }

    @Test fun manyChangesAreMedium() {
        var h = VolatilityChecks.updatedHistory(app(label = "A", at = 1), null)
        listOf("B", "C", "D").forEachIndexed { i, l -> h = VolatilityChecks.updatedHistory(app(label = l, at = 2L + i), h) }
        val f = VolatilityChecks.run(h.entries).first { it.id == "CHANGED_LABEL" }
        assertEquals(Severity.MEDIUM, f.severity)
        assertTrue(f.title.contains("3 lần"))
    }

    // ---------- Thống kê và báo cáo ----------

    @Test fun deviceStatsMatchCounts() {
        val a = app(certs = listOf(cert("1", "CN" to "X")))
        val b = app(certs = listOf(fullCert)).copy(packageName = "com.b")
        val ha = VolatilityChecks.updatedHistory(a, null)
        val hb = VolatilityChecks.updatedHistory(b, null)
        val reports = listOf(Analyzer.analyze(a, ha), Analyzer.analyze(b, hb))
        val stats = DeviceStats.compute(reports, mapOf(a.packageName to ha, b.packageName to hb))
        val missingO = stats[0].rows.first { it.label.startsWith("Thiếu O ") }
        assertEquals(1, missingO.count)
        assertEquals(2, missingO.total)
        assertEquals("50.0%", missingO.percentText)
        // Chưa app nào được quét 2 lần -> mẫu số biến động bằng 0.
        assertEquals(0, stats[3].rows.first().total)
        val md = MarkdownReport.build(reports, stats, 0)
        assertTrue(md.contains("| Thiếu O (organization) | 1/2 | 50.0% |"))
    }

    @Test fun normalizerIgnoresPunctuationAndAccents() {
        assertTrue(Normalizer.same("Cube Apps, Ltd.", "cube apps ltd"))
        assertTrue(Normalizer.same("Công ty Đất Việt", "cong ty dat viet"))
        assertFalse(Normalizer.same("Cube Apps", "Cube Studio"))
        assertTrue(Normalizer.same(null, " "))
    }
}
