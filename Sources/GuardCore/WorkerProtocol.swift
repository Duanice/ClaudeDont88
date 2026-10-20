import Foundation

/// Private anonymous-pipe protocol. A worker has no privileges beyond the calling user.
public struct WorkerRequest: Codable {
    public let executable: String
    public let arguments: [String]
    public let environment: [String: String]
    public let outputPath: String?
    public let cleanupDirectory: String?
    public let detachedExecutable: String?
    public let detachedArgument: String?

    public init(executable: String, arguments: [String], environment: [String: String],
                outputPath: String? = nil, cleanupDirectory: String? = nil,
                detachedExecutable: String? = nil, detachedArgument: String? = nil) {
        self.executable = executable; self.arguments = arguments; self.environment = environment
        self.outputPath = outputPath; self.cleanupDirectory = cleanupDirectory
        self.detachedExecutable = detachedExecutable; self.detachedArgument = detachedArgument
    }
}

public struct WorkerEvent: Codable {
    public let pid: Int32?
    public let status: Int32?
    public let reason: String?
    public let observedDescendants: Int?
    public let signalErrors: Int?
    public init(pid: Int32? = nil, status: Int32? = nil, reason: String? = nil,
                observedDescendants: Int? = nil, signalErrors: Int? = nil) {
        self.pid = pid; self.status = status; self.reason = reason
        self.observedDescendants = observedDescendants; self.signalErrors = signalErrors
    }
}
