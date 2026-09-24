import Foundation

/// Reads the `MUB1` password filter written by `tools/build_intel.py`.
///
/// A Bloom filter is the *correct* structure here, not a compromise: its only
/// error is a false positive, which tells someone to change a password that was
/// actually fine. False negatives are impossible, so a breached password can
/// never be reported as safe. The error mode points the safe way.
public struct BloomFilter: Sendable {

    public static let magic = "MUB1"
    public static let headerBytes = 40
    private static let formatVersion: UInt32 = 1

    private let bits: [UInt64]
    public let bitCount: UInt64
    public let hashCount: Int
    public let insertedCount: UInt64

    public enum ParseError: Error, CustomStringConvertible {
        case truncated(have: Int, need: Int)
        case badMagic(String)
        case unsupportedVersion(UInt32)
        case corrupt

        public var description: String {
            switch self {
            case .truncated(let have, let need): "truncated bundle: have \(have) bytes, need \(need)"
            case .badMagic(let m): "bad magic '\(m)', expected '\(BloomFilter.magic)'"
            case .unsupportedVersion(let v): "unsupported bloom format version \(v)"
            case .corrupt: "bundle is corrupt: checksum mismatch"
            }
        }
    }

    public init(data: Data, verifyChecksum: Bool = true) throws {
        guard data.count >= Self.headerBytes else {
            throw ParseError.truncated(have: data.count, need: Self.headerBytes)
        }
        let bytes = [UInt8](data)

        let magic = String(decoding: bytes[0..<4], as: UTF8.self)
        guard magic == Self.magic else { throw ParseError.badMagic(magic) }

        let version = Self.readUInt32(bytes, 4)
        guard version == Self.formatVersion else { throw ParseError.unsupportedVersion(version) }

        hashCount = Int(Self.readUInt32(bytes, 8))
        bitCount = Self.readUInt64(bytes, 16)
        insertedCount = Self.readUInt64(bytes, 24)
        let checksum = Self.readUInt64(bytes, 32)

        let wordCount = Int((bitCount + 63) / 64)
        let need = Self.headerBytes + wordCount * 8
        guard bytes.count >= need else { throw ParseError.truncated(have: bytes.count, need: need) }

        var words = [UInt64](repeating: 0, count: wordCount)
        for i in 0..<wordCount {
            words[i] = Self.readUInt64(bytes, Self.headerBytes + i * 8)
        }
        bits = words

        if verifyChecksum, Self.checksum(of: words) != checksum {
            throw ParseError.corrupt
        }
    }

    /// - Returns: `false` = definitely absent. `true` = probably present.
    public func contains(_ value: String) -> Bool {
        let utf8 = Array(value.utf8)
        var probe = Hashing.h1(utf8)
        let step = Hashing.h2(utf8)
        for _ in 0..<hashCount {
            let index = probe % bitCount
            let word = Int(index >> 6)
            let bit = UInt64(index & 63)
            if (bits[word] >> bit) & 1 == 0 { return false }
            probe = probe &+ step
        }
        return true
    }

    /// Measured fill, used by the diagnostics screen so the claimed accuracy is
    /// something the user can see rather than something we assert.
    public func fillRatio() -> Double {
        let set = bits.reduce(0) { $0 + $1.nonzeroBitCount }
        return Double(set) / Double(bitCount)
    }

    static func checksum(of words: [UInt64]) -> UInt64 {
        var h: UInt64 = 0xCBF2_9CE4_8422_2325
        for w in words {
            var x = w
            for _ in 0..<8 {
                h ^= (x & 0xFF)
                h = h &* 0x0000_0100_0000_01B3
                x >>= 8
            }
        }
        return h
    }

    private static func readUInt32(_ b: [UInt8], _ at: Int) -> UInt32 {
        UInt32(b[at]) | (UInt32(b[at + 1]) << 8) | (UInt32(b[at + 2]) << 16) | (UInt32(b[at + 3]) << 24)
    }

    private static func readUInt64(_ b: [UInt8], _ at: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in stride(from: 7, through: 0, by: -1) {
            v = (v << 8) | UInt64(b[at + i])
        }
        return v
    }
}

/// Reads the `MUS1` exact domain table.
///
/// Exact, not approximate, because here a false positive blocks a site the user
/// needs — the feature looks broken, they switch it off, and lose all of its
/// protection. There is no safe direction to be wrong in.
public struct SortedHashSet64: Sendable {

    public static let magic = "MUS1"
    public static let headerBytes = 24
    private static let buckets = 1 << 16

    private let digests: [UInt64]
    private let index: [Int]

    public var count: Int { digests.count }

    public init(data: Data, verifyChecksum: Bool = true) throws {
        guard data.count >= Self.headerBytes else {
            throw BloomFilter.ParseError.truncated(have: data.count, need: Self.headerBytes)
        }
        let bytes = [UInt8](data)

        let magic = String(decoding: bytes[0..<4], as: UTF8.self)
        guard magic == Self.magic else { throw BloomFilter.ParseError.badMagic(magic) }

        let count = Int(Self.readUInt64(bytes, 8))
        let checksum = Self.readUInt64(bytes, 16)
        let need = Self.headerBytes + count * 8
        guard bytes.count >= need else {
            throw BloomFilter.ParseError.truncated(have: bytes.count, need: need)
        }

        var values = [UInt64](repeating: 0, count: count)
        for i in 0..<count {
            values[i] = Self.readUInt64(bytes, Self.headerBytes + i * 8)
        }

        if verifyChecksum, BloomFilter.checksum(of: values) != checksum {
            throw BloomFilter.ParseError.corrupt
        }
        // A mis-sorted table would make the binary search return false
        // negatives -- precisely what this structure exists to avoid.
        for i in 1..<max(count, 1) where values[i - 1] >= values[i] {
            throw BloomFilter.ParseError.corrupt
        }

        digests = values

        var idx = [Int](repeating: 0, count: Self.buckets + 1)
        var pos = 0
        for bucket in 0..<Self.buckets {
            idx[bucket] = pos
            while pos < values.count && Int(values[pos] >> 48) == bucket { pos += 1 }
        }
        idx[Self.buckets] = values.count
        index = idx
    }

    public func contains(_ value: String) -> Bool {
        containsDigest(Hashing.digest(value))
    }

    public func containsDigest(_ digest: UInt64) -> Bool {
        let bucket = Int(digest >> 48)
        var lo = index[bucket], hi = index[bucket + 1]
        while lo < hi {
            let mid = (lo + hi) / 2
            if digests[mid] < digest { lo = mid + 1 }
            else if digests[mid] > digest { hi = mid }
            else { return true }
        }
        return false
    }

    /// Returns which entry matched, so the UI can explain a block rather than
    /// just performing one.
    public func matchDomain(_ domain: String, maxLabels: Int = 5) -> String? {
        DomainNormalizer.parentChain(domain, maxLabels: maxLabels).first(where: contains)
    }

    private static func readUInt64(_ b: [UInt8], _ at: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in stride(from: 7, through: 0, by: -1) {
            v = (v << 8) | UInt64(b[at + i])
        }
        return v
    }
}

/// Timezone-free `yyyy-MM-dd` arithmetic.
///
/// `Calendar` and `DateFormatter` drag in locale, timezone and calendar-system
/// behaviour that differs from the JVM in ways that would break parity. Patch
/// levels are pure civil dates with no zone involved, so the two lines of
/// arithmetic are written out directly (Howard Hinnant's `days_from_civil`),
/// exactly as in `IsoDate.kt`.
public enum IsoDate {

    public static func toEpochDay(_ value: String) -> Int64? {
        let parts = value.trimmingCharacters(in: .whitespaces).split(separator: "-")
        guard parts.count == 3,
              parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
              let y = Int(parts[0]), let m = Int(parts[1]), let d = Int(parts[2]),
              (1...12).contains(m), d >= 1, d <= daysInMonth(y, m)
        else { return nil }
        return daysFromCivil(y, m, d)
    }

    public static func daysBetween(_ from: String, _ to: String) -> Int64? {
        guard let a = toEpochDay(from), let b = toEpochDay(to) else { return nil }
        return b - a
    }

    public static func isValid(_ value: String) -> Bool { toEpochDay(value) != nil }

    private static func isLeap(_ y: Int) -> Bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

    private static func daysInMonth(_ y: Int, _ m: Int) -> Int {
        switch m {
        case 1, 3, 5, 7, 8, 10, 12: 31
        case 4, 6, 9, 11: 30
        case 2: isLeap(y) ? 29 : 28
        default: 0
        }
    }

    private static func daysFromCivil(_ year: Int, _ month: Int, _ day: Int) -> Int64 {
        let y = Int64(month <= 2 ? year - 1 : year)
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = Int64((month + 9) % 12)
        let doy = (153 * mp + 2) / 5 + Int64(day) - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }
}
