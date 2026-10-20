import Foundation
import Security
import GuardCore

public enum CodeIdentity {
    private static func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey:
                            (SecCopyErrorMessageString(status, nil) as String?) ?? "Code signature error"])
        }
    }

    public static func inspect(_ url: URL) throws -> TargetIdentity {
        var code: SecStaticCode?
        try check(SecStaticCodeCreateWithPath(url as CFURL, [], &code))
        guard let code else { throw PolicyError.invalid("Cannot read executable signature") }
        try check(SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil))
        var requirement: SecRequirement?
        try check(SecCodeCopyDesignatedRequirement(code, [], &requirement))
        guard let requirement else { throw PolicyError.invalid("Missing designated requirement") }
        var text: CFString?
        try check(SecRequirementCopyString(requirement, [], &text))
        guard let text else { throw PolicyError.invalid("Cannot read designated requirement") }
        return TargetIdentity(label: url.lastPathComponent, requirement: text as String)
    }

    public static func compile(_ identity: TargetIdentity) throws -> SecRequirement {
        var requirement: SecRequirement?
        try check(SecRequirementCreateWithString(identity.requirement as CFString, [], &requirement))
        guard let requirement else { throw PolicyError.invalid("Invalid code requirement") }
        return requirement
    }

    public static func resolve(auditToken: Data) -> SecCode? {
        // audit_token_t is eight uint32_t values. No PID lookup or process-name fallback.
        guard auditToken.count == 32 else { return nil }
        let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    public static func matches(_ code: SecCode, requirement: SecRequirement) -> Bool {
        SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}

public final class CompiledPolicy {
    public let policy: GuardPolicy
    private let requirements: [SecRequirement]

    public init(_ policy: GuardPolicy) throws {
        try policy.validate()
        self.policy = policy
        self.requirements = try policy.targets.map(CodeIdentity.compile)
    }

    public func classify(appToken: Data?, processToken: Data?) -> Attribution {
        var resolved = 0
        for token in [appToken, processToken].compactMap({ $0 }) {
            guard let code = CodeIdentity.resolve(auditToken: token) else { continue }
            resolved += 1
            if requirements.contains(where: { CodeIdentity.matches(code, requirement: $0) }) {
                return .protected
            }
        }
        // A system delegate alone cannot prove the originating app is unrelated.
        return resolved == 2 ? .other : .unknown
    }
}
