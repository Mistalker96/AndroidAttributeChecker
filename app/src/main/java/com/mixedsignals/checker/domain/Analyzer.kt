package com.mixedsignals.checker.domain

import com.mixedsignals.checker.domain.model.AppReport
import com.mixedsignals.checker.domain.model.AppSignals
import com.mixedsignals.checker.domain.model.ConfidenceLevel
import com.mixedsignals.checker.domain.model.Finding
import com.mixedsignals.checker.domain.model.PackageHistory

/** Ghép các bộ kiểm tra và tính điểm cho một app. */
object Analyzer {

    /**
     * @param history lịch sử của package *đã bao gồm* lần quét hiện tại
     *                (kết quả của [VolatilityChecks.updatedHistory]); null với file APK rời.
     */
    fun analyze(s: AppSignals, history: PackageHistory?): AppReport {
        val entries = history?.entries.orEmpty()
        val findings = (AvailabilityChecks.run(s) + VolatilityChecks.run(entries))
            .sortedWith(compareBy<Finding> { it.severity.ordinal }.thenBy { it.group.ordinal })
        val score = score(findings)
        return AppReport(
            signals = s,
            findings = findings,
            history = entries,
            changes = VolatilityChecks.changes(entries),
            score = score,
            level = level(score),
        )
    }

    /** 100 trừ tổng trọng số: HIGH 25, MEDIUM 10, LOW 4, INFO 0. */
    fun score(findings: List<Finding>): Int =
        (100 - findings.sumOf { it.severity.weight }).coerceIn(0, 100)

    fun level(score: Int): ConfidenceLevel = when {
        score >= 80 -> ConfidenceLevel.CLEAR
        score >= 50 -> ConfidenceLevel.AMBIGUOUS
        else -> ConfidenceLevel.UNCLEAR
    }
}
