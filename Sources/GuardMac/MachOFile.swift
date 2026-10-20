import Foundation
import GuardCore

// Read only bounded headers; a Claude binary can be hundreds of megabytes.
enum MachOFile {
    enum Kind: Equatable { case executable, library, other }

    static func kind(at url: URL) throws -> Kind {
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        let size = try file.seekToEnd()
        func read(_ offset: UInt64, _ length: Int) throws -> [UInt8] {
            guard offset <= size, UInt64(length) <= size - offset else {
                throw PolicyError.invalid("Truncated Mach-O header")
            }
            try file.seek(toOffset: offset)
            let bytes = Array(try file.read(upToCount: length) ?? Data())
            guard bytes.count == length else { throw PolicyError.invalid("Cannot read Mach-O header") }
            return bytes
        }
        func number(_ bytes: [UInt8], _ offset: Int, _ count: Int, little: Bool = false) -> UInt64 {
            let slice = bytes[offset..<(offset + count)]
            return (little ? Array(slice.reversed()) : Array(slice)).reduce(0) { ($0 << 8) | UInt64($1) }
        }
        func thin(_ offset: UInt64, _ length: UInt64) throws -> Kind {
            guard length >= 16 else { throw PolicyError.invalid("Truncated Mach-O slice") }
            let bytes = try read(offset, 16)
            let magic = number(bytes, 0, 4)
            guard [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].contains(magic) else {
                throw PolicyError.invalid("Invalid Mach-O slice")
            }
            let type = number(bytes, 12, 4, little: magic == 0xcefaedfe || magic == 0xcffaedfe)
            return type == 2 ? .executable : .library
        }
        guard size >= 4 else { return .other }
        let magic = number(try read(0, 4), 0, 4)
        if [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].contains(magic) {
            return try thin(0, size)
        }
        guard [0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca].contains(magic) else { return .other }
        let little = magic == 0xbebafeca || magic == 0xbfbafeca
        let is64 = magic == 0xcafebabf || magic == 0xbfbafeca
        let count = number(try read(0, 8), 4, 4, little: little)
        guard (1...64).contains(count) else { throw PolicyError.invalid("Invalid Mach-O slice count") }
        let stride = is64 ? 32 : 20
        let tableEnd = 8 + Int(count) * stride
        let table = try read(0, tableEnd)
        var kinds: [Kind] = []
        for index in 0..<Int(count) {
            let start = 8 + index * stride
            let offset = number(table, start + 8, is64 ? 8 : 4, little: little)
            let length = number(table, start + (is64 ? 16 : 12), is64 ? 8 : 4, little: little)
            guard offset >= UInt64(tableEnd), offset <= size, length <= size - offset else {
                throw PolicyError.invalid("Invalid Mach-O slice bounds")
            }
            kinds.append(try thin(offset, length))
        }
        guard let first = kinds.first, kinds.allSatisfy({ $0 == first }) else {
            throw PolicyError.invalid("Inconsistent Mach-O slice types")
        }
        return first
    }
}
