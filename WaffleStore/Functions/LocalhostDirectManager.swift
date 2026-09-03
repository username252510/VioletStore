//
//  LocalhostDirectManager.swift
//  WaffleStore
//
//  Downloads and stores *.localhost.direct certificate bundles, used for the
//  two "HTTPS (localhost.direct)" install methods. See
//  https://github.com/Upinel/localhost.direct.
//
//  Their README offers two bundles, both supported here as separate Variants
//  sharing the same fetch/extract/store logic:
//
//  - .selfSigned ("Option A" in their README): their explicitly recommended,
//    stable choice - immune to CA revocation, 10-year validity. Because it's
//    self-signed, iOS won't trust it automatically; the user has to install
//    and trust it once via the .mobileconfig flow below.
//  - .publicCA ("Option B"): auto-trusted by iOS with zero setup, since it's
//    issued by a real CA. The tradeoff is the one that just took
//    backloop.dev down - per their own changelog this bundle has been
//    repeatedly leaked and revoked. Refreshed more eagerly than the
//    self-signed one as a result.
//
//  License note: like backloop.dev, both bundles are localhost.direct's
//  property, password-protected specifically to discourage exactly the kind
//  of bulk/automated redistribution a sideloading tool's userbase could look
//  like from their side. We never bundle either in the IPA - each is fetched
//  fresh onto each user's own device the first time they pick that install
//  method.
//

import Foundation
import Zip

enum LocalhostDirectManager {
    enum Variant {
        case selfSigned
        case publicCA

        var bundleURL: String {
            switch self {
            case .selfSigned: return "https://aka.re/localhost-ss"
            case .publicCA: return "https://aka.re/localhost"
            }
        }

        var bundlePassword: String {
            switch self {
            case .selfSigned: return "localhost"
            case .publicCA: return "IWillNotPutKeyFileInPublicAccessiblePlace.X1YKK"
            }
        }

        var certFilename: String {
            switch self {
            case .selfSigned: return "localhostdirect-ss-server.crt"
            case .publicCA: return "localhostdirect-ca-server.crt"
            }
        }

        var keyFilename: String {
            switch self {
            case .selfSigned: return "localhostdirect-ss-server.key"
            case .publicCA: return "localhostdirect-ca-server.key"
            }
        }

        /// The self-signed bundle is good for 10 years, so refreshing it is
        /// basically just a yearly sanity check. The public-CA bundle has a
        /// real history of getting revoked without warning (see their
        /// changelog), so we check it much more eagerly - closer to how
        /// backloop.dev's weekly rotation worked - to catch a reissue or a
        /// dead cert sooner rather than later.
        var refreshInterval: TimeInterval {
            switch self {
            case .selfSigned: return 60 * 60 * 24 * 180
            case .publicCA: return 60 * 60 * 24 * 4
            }
        }
    }

    static let hostName = "localhost.direct"

    private static var documentsURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    }

    static func certificateURL(for variant: Variant) -> URL {
        documentsURL.appendingPathComponent(variant.certFilename)
    }

    static func privateKeyURL(for variant: Variant) -> URL {
        documentsURL.appendingPathComponent(variant.keyFilename)
    }

    static func hasCertificates(for variant: Variant) -> Bool {
        FileManager.default.fileExists(atPath: certificateURL(for: variant).path) &&
        FileManager.default.fileExists(atPath: privateKeyURL(for: variant).path)
    }

    static func needsRefresh(for variant: Variant) -> Bool {
        guard
            hasCertificates(for: variant),
            let attrs = try? FileManager.default.attributesOfItem(atPath: certificateURL(for: variant).path),
            let modified = attrs[.modificationDate] as? Date
        else {
            return true
        }
        return Date().timeIntervalSince(modified) > variant.refreshInterval
    }

    static func updateIfNeeded(for variant: Variant, completion: @escaping (Bool) -> Void) {
        guard needsRefresh(for: variant) else {
            completion(true)
            return
        }
        update(for: variant, completion: completion)
    }

    /// Downloads the password-protected bundle, extracts it (reusing the
    /// Zip dependency this project already has for IPA packing - it
    /// supports password-protected zips too), and stores the .crt/.key pair
    /// in Documents. Safe to fail quietly with no connectivity; the install
    /// flow just falls back to plain HTTP/127.0.0.1 in that case.
    static func update(for variant: Variant, completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: variant.bundleURL) else {
            completion(false)
            return
        }

        URLSession.shared.dataTask(with: url) { data, _, error in
            guard error == nil, let data else {
                DispatchQueue.main.async { completion(false) }
                return
            }

            let fm = FileManager.default
            let workDir = fm.temporaryDirectory.appendingPathComponent("localhostdirect-\(UUID().uuidString)")
            let zipPath = workDir.appendingPathComponent("bundle.zip")
            let extractedDir = workDir.appendingPathComponent("extracted")

            do {
                try fm.createDirectory(at: workDir, withIntermediateDirectories: true)
                try data.write(to: zipPath)
                try Zip.unzipFile(zipPath, destination: extractedDir, overwrite: true, password: variant.bundlePassword)

                // The README's own nginx/Node.js examples reference
                // "localhost.direct.crt" / "localhost.direct.key" by name,
                // but we search rather than hardcode the path in case
                // they're nested in a subfolder or renamed in a future
                // reissue - first *.crt and first *.key found anywhere in
                // the archive.
                guard
                    let crtPath = firstFile(under: extractedDir, extension: "crt", fileManager: fm),
                    let keyPath = firstFile(under: extractedDir, extension: "key", fileManager: fm)
                else {
                    throw CocoaError(.fileReadUnknown)
                }

                let destCert = certificateURL(for: variant)
                let destKey = privateKeyURL(for: variant)
                if fm.fileExists(atPath: destCert.path) {
                    try fm.removeItem(at: destCert)
                }
                if fm.fileExists(atPath: destKey.path) {
                    try fm.removeItem(at: destKey)
                }
                try fm.copyItem(at: crtPath, to: destCert)
                try fm.copyItem(at: keyPath, to: destKey)

                try? fm.removeItem(at: workDir)
                DispatchQueue.main.async { completion(true) }
            } catch {
                try? fm.removeItem(at: workDir)
                DispatchQueue.main.async { completion(false) }
            }
        }.resume()
    }

    private static func firstFile(under directory: URL, extension ext: String, fileManager fm: FileManager) -> URL? {
        guard let enumerator = fm.enumerator(at: directory, includingPropertiesForKeys: nil) else {
            return nil
        }
        for case let fileURL as URL in enumerator {
            if fileURL.pathExtension.lowercased() == ext.lowercased() {
                return fileURL
            }
        }
        return nil
    }

    // MARK: - Trust profile (self-signed variant only)

    /// Builds a .mobileconfig that installs the self-signed localhost.direct
    /// cert as a trusted root. Doesn't apply to the public-CA variant, which
    /// is already trusted automatically. Installing the profile only gets
    /// you halfway on iOS: after that, the user still has to go to
    /// Settings > General > About > Certificate Trust Settings and flip
    /// "Full Trust" for it by hand. There's no way for a regular (non-MDM)
    /// app to do that second step for them - this is the same two-step
    /// dance any tool that needs a custom root CA on iOS (Charles Proxy,
    /// mitmproxy, etc.) requires.
    static func makeTrustProfileData() -> Data? {
        guard let pem = try? String(contentsOf: certificateURL(for: .selfSigned), encoding: .utf8) else {
            return nil
        }
        let base64 = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines)
            .joined()
        guard let derData = Data(base64Encoded: base64) else {
            return nil
        }

        let payloadUUID = UUID().uuidString
        let profileUUID = UUID().uuidString

        let profile: [String: Any] = [
            "PayloadContent": [[
                "PayloadCertificateFileName": "localhostdirect.cer",
                "PayloadContent": derData,
                "PayloadDescription": "Adds the localhost.direct root certificate so this device trusts VioletStore's local install server.",
                "PayloadDisplayName": "localhost.direct Root Certificate",
                "PayloadIdentifier": "xyz.c0n.violetstore.localhostdirect.cert.\(payloadUUID)",
                "PayloadType": "com.apple.security.root",
                "PayloadUUID": payloadUUID,
                "PayloadVersion": 1,
            ]],
            "PayloadDisplayName": "localhost.direct Certificate",
            "PayloadDescription": "Lets VioletStore install apps over HTTPS on cellular/hotspot using localhost.direct. After installing this profile, go to Settings > General > About > Certificate Trust Settings and enable full trust for \"localhost.direct\".",
            "PayloadIdentifier": "xyz.c0n.violetstore.localhostdirect.\(profileUUID)",
            "PayloadRemovalDisallowed": false,
            "PayloadType": "Configuration",
            "PayloadUUID": profileUUID,
            "PayloadVersion": 1,
        ]

        return try? PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: .zero)
    }
}
