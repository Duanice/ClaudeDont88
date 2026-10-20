import Foundation
import Security
import GuardCore

public enum ProfileStore {
    public static var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ClaudeDont88", isDirectory: true)
    }
    private static let key: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "io.github.duanice.ClaudeDont88.proxy",
        kSecAttrAccount as String: "upstream"
    ]

    public static func load() throws -> ProxyProfile {
        let url = directory.appendingPathComponent("proxy-profile.json")
        guard FileManager.default.fileExists(atPath: url.path) else { return ProxyProfile() }
        let data = try Data(contentsOf: url)
        guard data.count <= 16384 else { throw PolicyError.invalid("配置文件过大") }
        return try JSONDecoder().decode(ProxyProfile.self, from: data)
    }

    public static func password() throws -> String {
        var query = key
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return "" }
        guard status == errSecSuccess, let data = result as? Data, let text = String(data: data, encoding: .utf8) else {
            throw PolicyError.invalid("无法读取钥匙串凭据")
        }
        return text
    }

    public static func save(_ profile: ProxyProfile, password: String) throws {
        _ = try profile.configuration(password: password, localToken: UUID().uuidString)
        let attrs = [kSecValueData as String: Data(password.utf8)] as CFDictionary
        var status = SecItemUpdate(key as CFDictionary, attrs)
        if status == errSecItemNotFound {
            var item = key
            item[kSecValueData as String] = Data(password.utf8)
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw PolicyError.invalid("无法保存钥匙串凭据；配置未保存") }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let url = directory.appendingPathComponent("proxy-profile.json")
        try JSONEncoder().encode(profile).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
