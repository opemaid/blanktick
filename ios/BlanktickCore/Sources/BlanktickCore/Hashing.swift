import Foundation

/// Deterministic 64-bit hashing — the Swift member of a three-language contract.
///
/// The other two implementations are `tools/blanktick_hash.py` (which builds the
/// bundle) and `core/.../filters/Hashing.kt` (which reads it on Android). All
/// three must agree on every bit for every input.
///
/// Swift's own `Hasher` is deliberately seeded per process and would produce a
/// different answer on every launch, so it cannot be used here. `hashValue` is
/// 64-bit but unspecified across versions. Hence a hand-written specification:
///
/// ```
/// h1(x) = splitMix64( fnv1a64(x, OFFSET_A) )
/// h2(x) = splitMix64( fnv1a64(x, OFFSET_B) ^ 0xD6E8FEB86659FD93 )
/// ```
///
/// FNV-1a runs over the **UTF-8 bytes**, not UTF-16 code units — hashing
/// `String.utf16` here would silently break every non-ASCII key.
public enum Hashing {

    private static let fnvPrime: UInt64 = 0x0000_0100_0000_01B3
    private static let fnvOffsetA: UInt64 = 0xCBF2_9CE4_8422_2325
    private static let fnvOffsetB: UInt64 = 0x9E37_79B9_7F4A_7C15
    private static let h2Tweak: UInt64 = 0xD6E8_FEB8_6659_FD93

    /// SplitMix64. Strong avalanche; corrects FNV-1a's weak low bits, which is
    /// exactly where a modulo lands in a Bloom probe.
    @inlinable
    public static func mix(_ value: UInt64) -> UInt64 {
        var z = value &+ 0x9E37_79B9_7F4A_7C15
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    private static func fnv1a(_ bytes: some Sequence<UInt8>, offset: UInt64) -> UInt64 {
        var h = offset
        for b in bytes {
            h ^= UInt64(b)
            h = h &* fnvPrime
        }
        return h
    }

    public static func h1(_ bytes: some Sequence<UInt8>) -> UInt64 {
        mix(fnv1a(bytes, offset: fnvOffsetA))
    }

    public static func h2(_ bytes: some Sequence<UInt8>) -> UInt64 {
        mix(fnv1a(bytes, offset: fnvOffsetB) ^ h2Tweak)
    }

    public static func h1(_ s: String) -> UInt64 { h1(Array(s.utf8)) }
    public static func h2(_ s: String) -> UInt64 { h2(Array(s.utf8)) }

    /// Single digest, for the exact-membership tables.
    public static func digest(_ s: String) -> UInt64 { h1(s) }
}

/// Canonicalisation applied before hashing.
///
/// Must match `DomainNormalizer` in Kotlin and `normalize_domain` in Python
/// exactly, or a domain written into the bundle by one will never be found by
/// another.
public enum DomainNormalizer {

    /// Lowercases, drops a trailing dot, drops a leading `*.`, strips a port.
    ///
    /// `www.` is deliberately **not** stripped: `www.example.com` and
    /// `example.com` are different names, and `parentChain` handles the
    /// relationship at query time.
    public static func normalize(_ input: String) -> String {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.hasPrefix("*.") { s = String(s.dropFirst(2)) }
        while s.hasSuffix(".") { s = String(s.dropLast()) }
        if let colon = s.lastIndex(of: ":") {
            let port = s[s.index(after: colon)...]
            if !port.isEmpty, port.allSatisfy(\.isNumber), colon != s.startIndex {
                s = String(s[s.startIndex..<colon])
            }
        }
        return s
    }

    /// The domain then each parent, most specific first, capped at `maxLabels`.
    ///
    /// Never yields a bare TLD: one bad `com` line in a blocklist would
    /// otherwise block the internet.
    public static func parentChain(_ domain: String, maxLabels: Int = 5) -> [String] {
        let normalized = normalize(domain)
        guard !normalized.isEmpty else { return [] }
        let labels = normalized.split(separator: ".", omittingEmptySubsequences: true)
        guard labels.count >= 2 else { return [normalized] }

        var out: [String] = []
        var start = 0
        while start <= labels.count - 2 && out.count < maxLabels {
            out.append(labels[start...].joined(separator: "."))
            start += 1
        }
        return out
    }
}
