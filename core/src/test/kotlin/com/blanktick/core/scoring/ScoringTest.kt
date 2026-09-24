package com.blanktick.core.scoring

import com.blanktick.core.model.Category
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Grade
import com.blanktick.core.model.Platform
import com.blanktick.core.model.Severity
import kotlin.math.abs
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ApportionmentTest {

    @Test
    fun `parts always sum to the total`() {
        val rng = Random(20260828)
        repeat(2_000) {
            val n = rng.nextInt(1, 25)
            val weights = List(n) { rng.nextDouble(0.0, 30.0) }
            val total = rng.nextInt(0, 101)
            val parts = Apportionment.largestRemainder(weights, total)
            assertEquals(total, parts.sum(), "weights=$weights total=$total parts=$parts")
            assertEquals(n, parts.size)
            assertTrue(parts.all { it >= 0 })
        }
    }

    @Test
    fun `largest fractional remainders receive the leftover units`() {
        // Exact thirds of 10: 3.333 each. Two units left after flooring.
        val parts = Apportionment.largestRemainder(listOf(1.0, 1.0, 1.0), 10)
        assertEquals(10, parts.sum())
        assertEquals(listOf(4, 3, 3), parts, "ties must break by index for determinism")
    }

    @Test
    fun `proportionality is respected`() {
        val parts = Apportionment.largestRemainder(listOf(90.0, 10.0), 100)
        assertEquals(listOf(90, 10), parts)
    }

    @Test
    fun `zero total across zero weights is fine`() {
        assertEquals(listOf(0, 0), Apportionment.largestRemainder(listOf(0.0, 0.0), 0))
    }

    @Test
    fun `empty input with zero total`() {
        assertEquals(emptyList(), Apportionment.largestRemainder(emptyList(), 0))
    }

    @Test
    fun `distributing a positive total across zero weights is rejected`() {
        assertFailsWith<IllegalArgumentException> {
            Apportionment.largestRemainder(listOf(0.0, 0.0), 5)
        }
    }

    @Test
    fun `negative total is rejected`() {
        assertFailsWith<IllegalArgumentException> {
            Apportionment.largestRemainder(listOf(1.0), -1)
        }
    }

    @Test
    fun `non-finite weights are rejected`() {
        assertFailsWith<IllegalArgumentException> {
            Apportionment.largestRemainder(listOf(1.0, Double.NaN), 5)
        }
    }
}

class ScoringEngineTest {

    private val engine = ScoringEngine()
    private val policy = ScoringPolicy.DEFAULT

    private fun finding(
        id: String,
        severity: Severity,
        category: Category = Category.NETWORK,
        subject: String = "",
        multiplier: Double = 1.0
    ) = Finding(
        ruleId = id,
        category = category,
        severity = severity,
        title = "t",
        detail = "d",
        remediation = if (severity == Severity.INFO) "" else "fix it",
        subjectId = subject,
        weightMultiplier = multiplier
    )

    private fun score(vararg findings: Finding) =
        engine.score(findings.toList(), Platform.ANDROID, findings.size, 0, 0L)

    @Test
    fun `a clean device scores 100`() {
        val result = score()
        assertEquals(100, result.score)
        assertEquals(Grade.STRONG, result.grade)
        assertTrue(result.findings.isEmpty())
        assertTrue(result.deductionsReconcile)
    }

    @Test
    fun `a single high finding costs its full weight`() {
        val result = score(finding("A", Severity.HIGH))
        assertEquals(100 - 14, result.score)
        assertEquals(14, result.findings.single().deduction)
        assertTrue(result.deductionsReconcile)
    }

    @Test
    fun `INFO findings never cost points`() {
        val result = score(
            finding("A", Severity.INFO),
            finding("B", Severity.INFO, subject = "x")
        )
        assertEquals(100, result.score)
        assertTrue(result.findings.all { it.deduction == 0 })
        assertEquals(0, result.actionableFindings.size)
    }

    @Test
    fun `repeat findings in one category decay geometrically`() {
        // 14 + 14*0.6 + 14*0.36 = 27.44 -> 27.
        // DEVICE_INTEGRITY caps at 40, so the cap does not interfere here.
        val result = score(
            finding("A", Severity.HIGH, Category.DEVICE_INTEGRITY, subject = "1"),
            finding("A", Severity.HIGH, Category.DEVICE_INTEGRITY, subject = "2"),
            finding("A", Severity.HIGH, Category.DEVICE_INTEGRITY, subject = "3")
        )
        assertEquals(100 - 27, result.score)
        assertTrue(
            result.findings.first().deduction > result.findings.last().deduction,
            "the first instance must cost the most"
        )
        assertTrue(result.deductionsReconcile)
    }

    @Test
    fun `the cap wins when decay alone would exceed it`() {
        // Same three findings in NETWORK, whose cap is 25. Decayed they total
        // 27.44, so the cap binds and the deduction is exactly 25.
        val result = score(
            finding("A", Severity.HIGH, Category.NETWORK, subject = "1"),
            finding("A", Severity.HIGH, Category.NETWORK, subject = "2"),
            finding("A", Severity.HIGH, Category.NETWORK, subject = "3")
        )
        assertEquals(100 - policy.capFor(Category.NETWORK), result.score)
        assertEquals(policy.capFor(Category.NETWORK), result.categories.single().deduction)
        assertEquals(
            policy.capFor(Category.NETWORK),
            result.categories.single().cappedAt,
            "the UI must be able to tell the user this category was capped"
        )
        assertTrue(result.deductionsReconcile)
    }

    @Test
    fun `a category cannot exceed its cap`() {
        // Twenty CRITICALs in NETWORK. Uncapped this is ~62 points; the cap is 25.
        val findings = (1..20).map { finding("A", Severity.CRITICAL, subject = "s$it") }
        val result = engine.score(findings, Platform.ANDROID, 1, 0, 0L)
        val networkDeduction = result.categories.single().deduction
        assertEquals(policy.capFor(Category.NETWORK), networkDeduction)
        assertEquals(100 - 25, result.score)
        assertTrue(result.deductionsReconcile)
    }

    @Test
    fun `capped category still apportions the exact cap across its findings`() {
        val findings = (1..20).map { finding("A", Severity.CRITICAL, subject = "s$it") }
        val result = engine.score(findings, Platform.ANDROID, 1, 0, 0L)
        assertEquals(25, result.findings.sumOf { it.deduction })
    }

    @Test
    fun `one bad category cannot zero the score`() {
        val findings = (1..50).map {
            finding("A", Severity.CRITICAL, Category.APP_HYGIENE, subject = "s$it")
        }
        val result = engine.score(findings, Platform.ANDROID, 1, 0, 0L)
        // APP_HYGIENE caps at 35, so the floor for a single-category disaster is 65.
        assertEquals(65, result.score)
        assertTrue(result.score > 0, "a device bad in one area must not read as bad in every area")
    }

    @Test
    fun `bad in every category can reach zero`() {
        val findings = Category.entries.flatMap { category ->
            (1..10).map { finding("R-${category.name}", Severity.CRITICAL, category, "s$it") }
        }
        val result = engine.score(findings, Platform.ANDROID, 6, 0, 0L)
        assertEquals(0, result.score)
        assertEquals(Grade.AT_RISK, result.grade)
        assertTrue(result.deductionsReconcile)
    }

    @Test
    fun `displayed deductions always reconcile with the score`() {
        val rng = Random(4242)
        val severities = Severity.entries
        repeat(1_000) {
            val findings = (1..rng.nextInt(1, 30)).map { i ->
                finding(
                    id = "R${rng.nextInt(5)}",
                    severity = severities[rng.nextInt(severities.size)],
                    category = Category.entries[rng.nextInt(Category.entries.size)],
                    subject = "s$i"
                )
            }
            val result = engine.score(findings, Platform.ANDROID, findings.size, 0, 0L)
            assertTrue(
                result.deductionsReconcile,
                "score=${result.score} sum=${result.findings.sumOf { it.deduction }}"
            )
            assertTrue(result.score in 0..100)
        }
    }

    @Test
    fun `identical inputs in any order produce identical output`() {
        val findings = listOf(
            finding("C", Severity.MEDIUM, Category.APP_HYGIENE, "z"),
            finding("A", Severity.CRITICAL, Category.NETWORK, "a"),
            finding("B", Severity.LOW, Category.DATA_EXPOSURE, "m"),
            finding("A", Severity.CRITICAL, Category.NETWORK, "b")
        )
        val first = engine.score(findings, Platform.ANDROID, 4, 0, 0L)
        val shuffled = engine.score(findings.reversed(), Platform.ANDROID, 4, 0, 0L)

        assertEquals(first.score, shuffled.score)
        assertEquals(
            first.findings.map { it.finding.key to it.deduction },
            shuffled.findings.map { it.finding.key to it.deduction },
            "ordering of the input must not change the output"
        )
    }

    @Test
    fun `duplicate keys are charged only once`() {
        val duplicate = finding("A", Severity.HIGH, subject = "same")
        val result = engine.score(listOf(duplicate, duplicate), Platform.ANDROID, 1, 0, 0L)
        assertEquals(1, result.findings.size)
        assertEquals(100 - 14, result.score)
    }

    @Test
    fun `weight multiplier scales the deduction`() {
        val plain = score(finding("A", Severity.MEDIUM))
        val doubled = score(finding("A", Severity.MEDIUM, multiplier = 2.0))
        assertEquals(100 - 9, plain.score)
        assertEquals(100 - 18, doubled.score)
    }

    @Test
    fun `findings are ordered worst first`() {
        val result = score(
            finding("A", Severity.LOW),
            finding("B", Severity.CRITICAL),
            finding("C", Severity.MEDIUM)
        )
        assertEquals(
            listOf(Severity.CRITICAL, Severity.MEDIUM, Severity.LOW),
            result.findings.map { it.finding.severity }
        )
    }

    @Test
    fun `grade bands match the policy`() {
        assertEquals(Grade.STRONG, policy.gradeFor(100))
        assertEquals(Grade.STRONG, policy.gradeFor(90))
        assertEquals(Grade.GOOD, policy.gradeFor(89))
        assertEquals(Grade.GOOD, policy.gradeFor(75))
        assertEquals(Grade.FAIR, policy.gradeFor(74))
        assertEquals(Grade.FAIR, policy.gradeFor(50))
        assertEquals(Grade.WEAK, policy.gradeFor(49))
        assertEquals(Grade.WEAK, policy.gradeFor(25))
        assertEquals(Grade.AT_RISK, policy.gradeFor(24))
        assertEquals(Grade.AT_RISK, policy.gradeFor(0))
    }

    @Test
    fun `checksPassed never goes negative`() {
        val findings = (1..10).map { finding("A", Severity.HIGH, subject = "s$it") }
        val result = engine.score(findings, Platform.ANDROID, checksRun = 1, checksSkipped = 0, 0L)
        assertTrue(result.checksPassed >= 0)
    }

    @Test
    fun `raw deductions sum close to the integer total`() {
        val findings = listOf(
            finding("A", Severity.CRITICAL),
            finding("B", Severity.HIGH, Category.APP_HYGIENE),
            finding("C", Severity.MEDIUM, Category.DATA_EXPOSURE)
        )
        val result = engine.score(findings, Platform.ANDROID, 3, 0, 0L)
        val raw = result.findings.sumOf { it.rawDeduction }
        assertTrue(
            abs(raw - (100 - result.score)) <= 0.5,
            "raw=$raw integer=${100 - result.score}"
        )
    }
}

class ScoringPolicyTest {

    @Test
    fun `policy rejects an INFO weight`() {
        assertFailsWith<IllegalArgumentException> {
            ScoringPolicy(
                severityWeights = ScoringPolicy.DEFAULT.severityWeights + (Severity.INFO to 5.0)
            )
        }
    }

    @Test
    fun `policy rejects an out-of-range decay`() {
        assertFailsWith<IllegalArgumentException> { ScoringPolicy(decay = 0.0) }
        assertFailsWith<IllegalArgumentException> { ScoringPolicy(decay = 1.5) }
    }

    @Test
    fun `category caps sum above 100 so a fully bad device can reach zero`() {
        assertTrue(ScoringPolicy.DEFAULT.categoryCaps.values.sum() > 100)
    }

    @Test
    fun `no single category cap can zero the score by itself`() {
        assertTrue(
            ScoringPolicy.DEFAULT.categoryCaps.values.all { it < 100 },
            "one bad area must never read as a totally compromised device"
        )
    }

    @Test
    fun `every actionable severity outranks the one below it`() {
        val w = ScoringPolicy.DEFAULT.severityWeights
        assertTrue(w.getValue(Severity.CRITICAL) > w.getValue(Severity.HIGH))
        assertTrue(w.getValue(Severity.HIGH) > w.getValue(Severity.MEDIUM))
        assertTrue(w.getValue(Severity.MEDIUM) > w.getValue(Severity.LOW))
        assertTrue(w.getValue(Severity.LOW) > w.getValue(Severity.INFO))
    }
}
