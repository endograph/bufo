import CryptoKit
import Foundation
import Network

/// TLS 1.2 with a pre-shared key per pair of watchers (PLAN.md,
/// Authentication), as Froggy's mesh does it: the key is both the
/// encryption and the proof of identity, so there are no certificates.
enum PeerTLS {
    static func parameters(_ codes: [PairingCode]) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        for code in codes {
            sec_protocol_options_add_pre_shared_key(options, dispatchData(code.key), dispatchData(Data(code.identity.utf8)))
        }
        sec_protocol_options_append_tls_ciphersuite(options, tls_ciphersuite_t(rawValue: numericCast(TLS_PSK_WITH_AES_128_GCM_SHA256))!)
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv12)
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = 15
        tcp.keepaliveInterval = 5
        tcp.keepaliveCount = 3
        tcp.connectionTimeout = 5
        return NWParameters(tls: tls, tcp: tcp)
    }

    /// An HMAC of this TLS session's exporter secret under `key`: both ends
    /// derive the same secret only within this one session.
    static func proof(_ connection: NWConnection, key: Data) -> Data? {
        exporter(connection).map { Data(HMAC<SHA256>.authenticationCode(for: $0, using: SymmetricKey(data: key))) }
    }

    private static func exporter(_ connection: NWConnection) -> Data? {
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else { return nil }
        let label = "peer proof"
        let secret = label.withCString {
            sec_protocol_metadata_create_secret(metadata.securityProtocolMetadata, label.utf8.count, $0, 32)
        }
        return secret.map { Data($0 as DispatchData) }
    }

    static func verify(_ proof: Data, _ connection: NWConnection, key: Data) -> Bool {
        guard let secret = exporter(connection) else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: secret, using: SymmetricKey(data: key))
    }

    /// Whether two textual addresses name the same IP address.
    static func same(_ a: String, _ b: String) -> Bool {
        func bytes(_ text: String) -> Data? {
            let bare = String(text.split(separator: "%").first ?? "")
            return IPv4Address(bare)?.rawValue ?? IPv6Address(bare)?.rawValue
        }
        guard let x = bytes(a), let y = bytes(b) else { return false }
        return x == y
    }

    static func host(_ endpoint: NWEndpoint) -> String? {
        if case .hostPort(let host, _) = endpoint { "\(host)" } else { nil }
    }

    private static func dispatchData(_ data: Data) -> __DispatchData {
        data.withUnsafeBytes { DispatchData(bytes: $0) } as __DispatchData
    }
}

/// One peer connection, framed (`FrameReader`), on the watcher's queue.
/// While `onProof` is set, the first frame goes to it unparsed; every frame
/// after is a message. Anything malformed or oversized closes it.
final class PeerLink: @unchecked Sendable {
    let connection: NWConnection
    private var reader = FrameReader()
    private var closed = false
    var onProof: ((Data) -> Void)?
    var onMessage: (PeerMessage) -> Void = { _ in }
    var onClose: () -> Void = {}

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    /// Reads frames until the connection ends.
    func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: FrameReader.maxFrame) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            if let data, !data.isEmpty {
                do {
                    for body in try self.reader.take(data) where !self.closed {
                        if let proof = self.onProof {
                            self.onProof = nil
                            proof(body)
                        } else {
                            self.onMessage(try FrameReader.message(body))
                        }
                    }
                } catch {
                    self.close()
                    return
                }
            }
            if done || error != nil { self.close() } else { self.receive() }
        }
    }

    func send(_ message: PeerMessage, then: (@Sendable () -> Void)? = nil) {
        guard !closed, let frame = FrameReader.frame(message) else { return }
        connection.send(content: frame, completion: .contentProcessed { _ in then?() })
    }

    func sendProof(_ proof: Data) {
        guard !closed, let frame = FrameReader.frame(body: proof) else { return }
        connection.send(content: frame, completion: .contentProcessed { _ in })
    }

    func close() {
        guard !closed else { return }
        closed = true
        connection.cancel()
        onClose()
    }
}
