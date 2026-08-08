//
//  SSLCertificateManager.swift
//  WaffleStore
//
//  Downloads and stores the *.backloop.dev certificate pack so the local
//  install server can be reached over a real, publicly-trusted HTTPS
//  connection instead of plain http://127.0.0.1.
//
//  Why this exists: iOS blocks the itms-services install flow from reaching
//  a plain-HTTP loopback server while the device is on cellular data or a
//  personal hotspot. *.backloop.dev is a public DNS name that resolves back
//  to 127.0.0.1/::1 and ships a real Let's Encrypt certificate for itself,
//  so connecting to "https://<subdomain>.backloop.dev:<port>" reaches our
//  own local server while still looking like a normal, valid HTTPS
//  connection to iOS. This is the same technique used by Feather
//  (github.com/khcrysalis/Feather) for its "Fully Local" server install
//  method - see backloop.dev and Feather's HOW_IT_WORKS.md for details.
//

import Foundation

/// Decodes the JSON pack served at https://backloop.dev/pack.json.
/// The private key is delivered split across two fields (key1/key2) that
/// need concatenating back into one PEM block - see backloop.dev's own
/// documentation for why (it was previously a single field until a scraper
/// picked up the literal key from the JSON).
struct BackloopCertificatePack: Decodable {
    let cert: String
    let ca: String
    let key: String
    let commonName: String

    private enum RootKeys: String, CodingKey {
        case cert, ca, key1, key2, info
    }
    private enum InfoKeys: String, CodingKey {
        case domains
    }
    private enum DomainKeys: String, CodingKey {
        case commonName
    }

    init(from decoder: Decoder) throws {
        let root = try decoder.container(keyedBy: RootKeys.self)
        cert = try root.decode(String.self, forKey: .cert)
        ca = try root.decode(String.self, forKey: .ca)
        let key1 = try root.decode(String.self, forKey: .key1)
        let key2 = try root.decode(String.self, forKey: .key2)
        key = key1 + key2

        let info = try root.nestedContainer(keyedBy: InfoKeys.self, forKey: .info)
        let domains = try info.nestedContainer(keyedBy: DomainKeys.self, forKey: .domains)
        commonName = try domains.decode(String.self, forKey: .commonName)
    }
}

enum SSLCertificateManager {
    static let packURL = "https://backloop.dev/pack.json"

    private static var documentsURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    }

    static var certificateURL: URL { documentsURL.appendingPathComponent("server.crt") }
    static var privateKeyURL: URL { documentsURL.appendingPathComponent("server.pem") }
    static var caURL: URL { documentsURL.appendingPathComponent("server-ca.crt") }
    static var commonNameURL: URL { documentsURL.appendingPathComponent("commonName.txt") }

    /// The hostname to bind/advertise the local server as, e.g.
    /// "abcd1234.backloop.dev". Falls back to 127.0.0.1 (plain HTTP) if no
    /// certificate pack has been downloaded yet.
    static var commonName: String {
        (try? String(contentsOf: commonNameURL, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "127.0.0.1"
    }

    static var hasCertificates: Bool {
        FileManager.default.fileExists(atPath: certificateURL.path) &&
        FileManager.default.fileExists(atPath: privateKeyURL.path) &&
        FileManager.default.fileExists(atPath: commonNameURL.path)
    }

    /// backloop.dev rotates its certificate pack roughly weekly. We refresh a
    /// bit more eagerly than that (every 4 days) so a stale cert never has a
    /// chance to actually expire on someone who doesn't open the app daily.
    static var needsRefresh: Bool {
        guard
            hasCertificates,
            let attrs = try? FileManager.default.attributesOfItem(atPath: certificateURL.path),
            let modified = attrs[.modificationDate] as? Date
        else {
            return true
        }
        return Date().timeIntervalSince(modified) > 60 * 60 * 24 * 4
    }

    /// Only hits the network if we don't have certificates yet or they're
    /// due for a refresh. Safe to call on every downgrade attempt.
    static func updateIfNeeded(completion: @escaping (Bool) -> Void) {
        guard needsRefresh else {
            completion(true)
            return
        }
        update(completion: completion)
    }

    /// Downloads the latest pack and writes it to the Documents directory.
    /// Certificates are rotated weekly by backloop.dev, so this should be
    /// called from Settings (and it's fine to fail quietly if there's no
    /// connectivity - the install flow just falls back to plain HTTP/127.0.0.1
    /// in that case).
    static func update(completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: packURL) else {
            completion(false)
            return
        }

        URLSession.shared.dataTask(with: url) { data, _, error in
            guard
                error == nil,
                let data,
                let pack = try? JSONDecoder().decode(BackloopCertificatePack.self, from: data)
            else {
                DispatchQueue.main.async { completion(false) }
                return
            }

            do {
                try pack.cert.write(to: certificateURL, atomically: true, encoding: .utf8)
                try pack.key.write(to: privateKeyURL, atomically: true, encoding: .utf8)
                try pack.ca.write(to: caURL, atomically: true, encoding: .utf8)
                try pack.commonName.write(to: commonNameURL, atomically: true, encoding: .utf8)
                DispatchQueue.main.async { completion(true) }
            } catch {
                DispatchQueue.main.async { completion(false) }
            }
        }.resume()
    }
}
