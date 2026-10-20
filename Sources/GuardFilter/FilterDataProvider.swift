import Foundation
import Network
import NetworkExtension
import os
import GuardCore
import GuardMac

@objc(FilterDataProvider)
final class FilterDataProvider: NEFilterDataProvider {
    private let logger = Logger(subsystem: "io.github.duanice.ClaudeDont88", category: "filter")
    private let lock = NSLock()
    private var configuration: CompiledPolicy?
    private var stopping = true
    private var generation = UUID()
    private var tracked: [UUID: NEFilterSocketFlow] = [:]
    private let maxTrackedFlows = 4096

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        do {
            guard let data = filterConfiguration.vendorConfiguration?["policy"] as? Data else {
                throw PolicyError.invalid("Missing policy; protection has not started")
            }
            let configuration = try CompiledPolicy(GuardPolicy.decode(data))
            lock.lock()
            self.configuration = configuration
            stopping = true
            let generation = UUID()
            self.generation = generation
            lock.unlock()
            // Loopback bypasses defaultAction unless explicitly included.
            let networks: [(String, Int)] = [("127.0.0.1", 8), ("::1", 128)]
            let rules = networks.map { host, prefix in
                NEFilterRule(networkRule: NENetworkRule(
                    destinationNetworkEndpoint: .hostPort(host: .init(host), port: .init(rawValue: 0)!),
                    prefix: prefix, protocol: .any), action: .filterData)
            }
            apply(NEFilterSettings(rules: rules, defaultAction: .filterData)) { error in
                self.lock.lock()
                guard self.generation == generation else {
                    self.lock.unlock()
                    completionHandler(PolicyError.invalid("Filter stopped during startup"))
                    return
                }
                self.stopping = error != nil
                self.lock.unlock()
                if let error {
                    self.logger.error("SETTINGS_FAILED \(error.localizedDescription, privacy: .public)")
                } else {
                    self.logger.notice("FILTER_STARTED prototype; existing flows and failure behavior unqualified")
                }
                completionHandler(error)
            }
        } catch {
            logger.error("CONFIGURATION_FAILED \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
        }
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        lock.lock()
        defer { lock.unlock() }
        let attribution = configuration?.classify(
            appToken: flow.sourceAppAuditToken, processToken: flow.sourceProcessAuditToken) ?? .unknown
        let socket = flow as? NEFilterSocketFlow
        var host: String?
        var port: Int?
        if case let .hostPort(remoteHost, remotePort) = socket?.remoteFlowEndpoint {
            host = String(describing: remoteHost)
            port = Int(remotePort.rawValue)
        }
        let transport: Transport = socket?.socketProtocol == IPPROTO_TCP ? .tcp :
            socket?.socketProtocol == IPPROTO_UDP ? .udp : .other
        let decision = PolicyEngine.decide(
            FlowDescription(attribution: attribution, host: host, port: port,
                            transport: transport, outbound: flow.direction == .outbound),
            policy: configuration?.policy, stopping: stopping)
        switch decision {
        case .drop:
            logger.notice("DROP flow=\(flow.identifier.uuidString, privacy: .public)")
            return .drop()
        case .allowProxy:
            guard let socket, tracked.count < maxTrackedFlows else { return .drop() }
            tracked[flow.identifier] = socket
            logger.notice("PROXY_ENDPOINT_ALLOWED flow=\(flow.identifier.uuidString, privacy: .public); upstream unverified")
            let verdict = NEFilterNewFlowVerdict.filterDataVerdict(
                withFilterInbound: true, peekInboundBytes: 1,
                filterOutbound: true, peekOutboundBytes: 1)
            verdict.shouldReport = true
            return verdict
        case .allowOther:
            return .allow()
        case .uncovered:
            // shortcut: attribution gaps are passed to preserve unrelated apps; this prevents a zero-leak claim.
            logger.error("UNATTRIBUTED flow=\(flow.identifier.uuidString, privacy: .public); outside prototype coverage")
            return .allow()
        }
    }

    private func dataVerdict(for flow: NEFilterFlow, count: Int) -> NEFilterDataVerdict {
        lock.lock()
        defer { lock.unlock() }
        guard !stopping, tracked[flow.identifier] != nil else { return .drop() }
        // Retain callbacks instead of granting an unlimited lifetime allowance.
        return NEFilterDataVerdict(passBytes: count, peekBytes: 1)
    }

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int,
                                    readBytes: Data) -> NEFilterDataVerdict {
        dataVerdict(for: flow, count: readBytes.count)
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict {
        dataVerdict(for: flow, count: readBytes.count)
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        dataVerdict(for: flow, count: 0)
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        dataVerdict(for: flow, count: 0)
    }

    override func handle(_ report: NEFilterReport) {
        if report.event == .flowClosed, let flow = report.flow {
            lock.lock()
            tracked.removeValue(forKey: flow.identifier)
            lock.unlock()
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock()
        stopping = true
        generation = UUID()
        let flows = Array(tracked.values)
        tracked.removeAll()
        lock.unlock()
        for flow in flows { update(flow, using: .drop(), for: .any) }
        logger.notice("FILTER_STOPPED; no guarantee after extension removal or crash")
        completionHandler()
    }
}
