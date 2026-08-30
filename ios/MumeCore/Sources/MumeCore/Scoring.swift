import Foundation

// MARK: - Model
//
// Mirrors core/src/main/kotlin/com/mume/core/model/Model.kt. The raw values on
// the enums are the wire format used by the shared golden fixtures, so they are
// part of the contract and must not be renamed.

public enum Platform: String, Codable, Sendable { case android = "ANDROID", ios = "IOS" }

public enum Severity: String, Codable, Sendable, CaseIterable, Comparable {
    case info = "INFO", low = "LOW", medium = "MEDIUM", high = "HIGH", critical = "CRITICAL"

    /// Ordering is load-bearing: findings sort by severity descending for
    /// deterministic output, exactly as the Kotlin `ordinal` comparison does.
    public var rank: Int {
        switch self {
        case .info: 0
        case .low: 1
        case .medium: 2
        case .high: 3
        case .critical: 4
        }
    }

    public var isActionable: Bool { self != .info }

    public static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }
}

public enum Category: String, Codable, Sendable, CaseIterable {
    case deviceIntegrity = "DEVICE_INTEGRITY"
    case osCurrency = "OS_CURRENCY"
    case network = "NETWORK"
    case appHygiene = "APP_HYGIENE"
    case dataExposure = "DATA_EXPOSURE"
    case accountSecurity = "ACCOUNT_SECURITY"

    public var displayName: String {
        switch self {
        case .deviceIntegrity: "Device integrity"
        case .osCurrency: "System updates"
        case .network: "Network"
        case .appHygiene: "Apps"
        case .dataExposure: "Personal data"
        case .accountSecurity: "Access & accounts"
        }
    }

    /// Declaration order must match the Kotlin enum: the global sort uses it.
    public var ordinal: Int { Category.allCases.firstIndex(of: self)! }
}

public enum Grade: String, Codable, Sendable {
    case strong = "STRONG", good = "GOOD", fair = "FAIR", weak = "WEAK", atRisk = "AT_RISK"

    public var label: String {
        switch self {
        case .strong: "Strong"
        case .good: "Good"
        case .fair: "Fair"
        case .weak: "Weak"
        case .atRisk: "At risk"
        }
    }
}

public struct Finding: Codable, Sendable, Equatable {
    public let ruleId: String
    public let category: Category
    public let severity: Severity
    public let title: String
    public let detail: String
    public let remediation: String
    public let subjectId: String
    public let weightMultiplier: Double

    public init(
        ruleId: String, category: Category, severity: Severity,
        title: String = "", detail: String = "", remediation: String = "",
        subjectId: String = "", weightMultiplier: Double = 1.0
    ) {
        precondition(!ruleId.isEmpty, "ruleId must not be blank")
        precondition(weightMultiplier > 0, "weightMultiplier must be positive")
        precondition(severity == .info || !remediation.isEmpty || title.isEmpty,
                     "actionable finding \(ruleId) must carry a remediation")
        self.ruleId = ruleId
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail
        self.remediation = remediation
        self.subjectId = subjectId
        self.weightMultiplier = weightMultiplier
    }

    public var key: String { subjectId.isEmpty ? ruleId : "\(ruleId)#\(subjectId)" }
}

public struct ScoredFinding: Sendable, Equatable {
    public let finding: Finding
    public let deduction: Int
    public let rawDeduction: Double
}

public struct CategoryScore: Sendable, Equatable {
    public let category: Category
    public let deduction: Int
    public let cappedAt: Int?
    public let findingCount: Int
}

public struct ScanResult: Sendable {
    public let score: Int
    public let grade: Grade
    public let findings: [ScoredFinding]
    public let categories: [CategoryScore]
    public let checksRun: Int
    public let checksPassed: Int
    public let checksSkipped: Int
    public let platform: Platform

    public var actionableFindings: [ScoredFinding] { findings.filter(\.finding.severity.isActionable) }

    /// Invariant asserted by the test suite: displayed deductions must reconcile.
    public var deductionsReconcile: Bool {
        100 - findings.reduce(0) { $0 + $1.deduction } == score
    }
}

// MARK: - Policy

/// The normative scoring parameters. Every value mirrors `ScoringPolicy.kt`;
/// the shared fixtures fail if either side drifts.
public struct ScoringPolicy: Sendable {

    public static let version = "1.0.0"

    public let severityWeights: [Severity: Double]
    public let categoryCaps: [Category: Int]
    public let decay: Double
    public let gradeThresholds: [(Int, Grade)]

    public init(
        severityWeights: [Severity: Double] = [
            .info: 0.0, .low: 4.0, .medium: 9.0, .high: 14.0, .critical: 25.0
        ],
        categoryCaps: [Category: Int] = [
            .deviceIntegrity: 40, .osCurrency: 25, .network: 25,
            .appHygiene: 35, .dataExposure: 20, .accountSecurity: 20
        ],
        decay: Double = 0.6,
        gradeThresholds: [(Int, Grade)] = [
            (90, .strong), (75, .good), (50, .fair), (25, .weak), (0, .atRisk)
        ]
    ) {
        precondition(decay > 0 && decay <= 1)
        precondition(severityWeights[.info] == 0, "INFO findings must never deduct points")
        precondition(gradeThresholds.last?.0 == 0)
        self.severityWeights = severityWeights
        self.categoryCaps = categoryCaps
        self.decay = decay
        self.gradeThresholds = gradeThresholds
    }

    public static let `default` = ScoringPolicy()

    public func weight(for severity: Severity) -> Double { severityWeights[severity]! }
    public func cap(for category: Category) -> Int { categoryCaps[category]! }
    public func grade(for score: Int) -> Grade { gradeThresholds.first { score >= $0.0 }!.1 }
}

// MARK: - Apportionment

/// Distributes an integer total across fractional weights so the parts sum
/// **exactly** to the total (largest remainder / Hamilton's method).
///
/// Without this, eight findings each rounding up by 0.4 invent three points of
/// deduction the score does not reflect — and a user who checks our arithmetic
/// and finds it wrong has good reason to distrust everything else.
///
/// Ties break by index, which keeps Swift and Kotlin byte-identical.
enum Apportionment {

    static func largestRemainder(_ weights: [Double], total: Int) -> [Int] {
        precondition(total >= 0)
        precondition(weights.allSatisfy { $0 >= 0 && $0.isFinite })
        guard !weights.isEmpty else {
            precondition(total == 0)
            return []
        }

        let sum = weights.reduce(0, +)
        guard sum > 0 else {
            precondition(total == 0, "cannot distribute \(total) across all-zero weights")
            return Array(repeating: 0, count: weights.count)
        }

        let exact = weights.map { $0 / sum * Double(total) }
        var result = exact.map { Int($0.rounded(.down)) }
        var remaining = total - result.reduce(0, +)
        guard remaining > 0 else { return result }

        let order = exact.indices.sorted { a, b in
            let fa = exact[a] - exact[a].rounded(.down)
            let fb = exact[b] - exact[b].rounded(.down)
            return fa == fb ? a < b : fa > fb
        }

        var i = 0
        while remaining > 0 && i < order.count {
            result[order[i]] += 1
            remaining -= 1
            i += 1
        }
        if remaining > 0 { result[order[0]] += remaining }
        return result
    }
}

// MARK: - Engine

/// Turns findings into a score, deterministically.
///
/// Pure: no I/O, no clock, no randomness, no platform types. Given the same
/// findings and policy it returns the same result on every machine and in both
/// languages — the property the golden fixtures test.
public struct ScoringEngine: Sendable {

    private let policy: ScoringPolicy

    public init(policy: ScoringPolicy = .default) { self.policy = policy }

    public func score(
        findings: [Finding],
        platform: Platform,
        checksRun: Int,
        checksSkipped: Int
    ) -> ScanResult {
        // Deduplicate: two rules emitting the same key would double-charge.
        var seen = Set<String>()
        let unique = findings.filter { seen.insert($0.key).inserted }

        var effective: [String: Double] = [:]

        for category in Category.allCases {
            let group = unique.filter { $0.category == category }
            guard !group.isEmpty else { continue }

            let ordered = group.sorted(by: orderWithinCategory)
            let decayed = ordered.enumerated().map { rank, f in
                baseWeight(f) * pow(policy.decay, Double(rank))
            }
            let categoryRaw = decayed.reduce(0, +)
            let categoryDeduction = min(categoryRaw, Double(policy.cap(for: category)))
            let scale = categoryRaw > 0 ? categoryDeduction / categoryRaw : 0

            for (rank, f) in ordered.enumerated() {
                effective[f.key] = decayed[rank] * scale
            }
        }

        let ordered = unique.sorted(by: globalOrder)
        let weights = ordered.map { effective[$0.key] ?? 0 }

        let totalRaw = weights.reduce(0, +)
        let score = max(0, min(100, 100 - Int(totalRaw.rounded())))
        let displayed = Apportionment.largestRemainder(weights, total: 100 - score)

        let scored = zip(ordered.indices, ordered).map { i, f in
            ScoredFinding(finding: f, deduction: displayed[i], rawDeduction: weights[i])
        }

        let categories: [CategoryScore] = Category.allCases.compactMap { category in
            let inCategory = scored.filter { $0.finding.category == category }
            guard !inCategory.isEmpty else { return nil }
            let deduction = inCategory.reduce(0) { $0 + $1.deduction }
            let cap = policy.cap(for: category)
            return CategoryScore(
                category: category,
                deduction: deduction,
                cappedAt: deduction >= cap ? cap : nil,
                findingCount: inCategory.filter(\.finding.severity.isActionable).count
            )
        }

        let actionable = scored.filter(\.finding.severity.isActionable).count

        return ScanResult(
            score: score,
            grade: policy.grade(for: score),
            findings: scored,
            categories: categories,
            checksRun: checksRun,
            checksPassed: max(0, checksRun - actionable),
            checksSkipped: checksSkipped,
            platform: platform
        )
    }

    private func baseWeight(_ f: Finding) -> Double {
        policy.weight(for: f.severity) * f.weightMultiplier
    }

    private func orderWithinCategory(_ a: Finding, _ b: Finding) -> Bool {
        let wa = baseWeight(a), wb = baseWeight(b)
        if wa != wb { return wa > wb }
        if a.ruleId != b.ruleId { return a.ruleId < b.ruleId }
        return a.subjectId < b.subjectId
    }

    private func globalOrder(_ a: Finding, _ b: Finding) -> Bool {
        if a.severity.rank != b.severity.rank { return a.severity.rank > b.severity.rank }
        let wa = baseWeight(a), wb = baseWeight(b)
        if wa != wb { return wa > wb }
        if a.category.ordinal != b.category.ordinal { return a.category.ordinal < b.category.ordinal }
        if a.ruleId != b.ruleId { return a.ruleId < b.ruleId }
        return a.subjectId < b.subjectId
    }
}
