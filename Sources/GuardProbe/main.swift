import Foundation
import Network
import GuardCore
import GuardMac
import Darwin

func emit(_ object: [String: Any], code: Int32) -> Never {
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
    exit(code)
}

let args = Array(CommandLine.arguments.dropFirst())
if args.count == 2, args[0] == "identity" {
    do {
        let target = try CodeIdentity.inspect(URL(fileURLWithPath: args[1]))
        emit(["label": target.label, "requirement": target.requirement], code: 0)
    } catch { emit(["error": error.localizedDescription], code: 64) }
}
guard args.count == 4 || args.count == 5, args.first == "exchange",
      args[1] == "tcp" || args[1] == "udp",
      PolicyEngine.numericAddress(args[2]) != nil,
      let portValue = UInt16(args[3]), portValue > 0,
      let port = NWEndpoint.Port(rawValue: portValue) else {
    emit(["error": "Usage: guard-probe identity PATH | exchange tcp|udp NUMERIC_IP PORT [COUNT]"], code: 64)
}
let repetitions = args.count == 5 ? Int(args[4]) : 1
guard let repetitions, (1...60).contains(repetitions) else {
    emit(["error": "COUNT must be 1...60"], code: 64)
}
let queue = DispatchQueue(label: "guard-probe")
let connection = NWConnection(host: NWEndpoint.Host(args[2]), port: port,
                              using: args[1] == "tcp" ? .tcp : .udp)
var completed = 0
let payload = Data(("ClaudeDont88-probe-" + UUID().uuidString).utf8)

func exchange() {
    connection.send(content: payload, completion: .contentProcessed { error in
        if let error { emit(["result": "send_failed", "error": "\(error)", "echoes": completed], code: 2) }
        receive(Data())
    })
}

func receive(_ accumulated: Data) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: payload.count) { data, _, complete, error in
        if let error { emit(["result": "receive_failed", "error": "\(error)", "echoes": completed], code: 2) }
        let result = accumulated + (data ?? Data())
        if result.count == payload.count {
            guard result == payload else { emit(["result": "wrong_echo"], code: 2) }
            completed += 1
            if completed == repetitions {
                emit(["result": "echo_received", "echoes": completed, "transport": args[1]], code: 0)
            }
            queue.asyncAfter(deadline: .now() + 1) { exchange() }
        } else if complete || result.count > payload.count {
            emit(["result": "incomplete_echo", "echoes": completed], code: 2)
        } else {
            receive(result)
        }
    }
}

connection.stateUpdateHandler = { state in
    switch state {
    case .ready: exchange()
    case .failed(let error):
        emit(["result": "connection_failed", "error": "\(error)", "echoes": completed], code: 2)
    default: break
    }
}
queue.asyncAfter(deadline: .now() + Double(repetitions + 5)) {
    emit(["result": "timeout", "echoes": completed], code: 2)
}
connection.start(queue: queue)
dispatchMain()
