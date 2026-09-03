//
//  Downgrader.swift
//  PancakeStore
//
//  Created by Mineek on 19/10/2024.
//

import Foundation
import UIKit
import Vapor
import NIOSSL
import Zip
import SwiftUI
import SafariServices
import PartyUI

/// Keeps the local install server alive for the app's lifetime instead of
/// letting ARC deallocate it the moment `installAppVersion` returns (Vapor's
/// `Application` asserts/crashes if it's deallocated without an explicit
/// `shutdown()`). A new downgrade attempt shuts down any previous instance
/// before starting a fresh one.
private final class InstallServerHolder {
    static var current: Application?
}

/// `LoggingSystem.bootstrap` may only be called once per process - calling it
/// again on a second downgrade attempt crashes. Vapor's own environment setup
/// is computed lazily exactly once here and reused for every server we start.
private enum VaporEnvironment {
    static let shared: Vapor.Environment = {
        var env = try! Vapor.Environment.detect()
        try! LoggingSystem.bootstrap(from: &env)
        return env
    }()
}

struct SafariWebView: UIViewControllerRepresentable {
    let url: URL
    
    func makeUIViewController(context: Context) -> SFSafariViewController {
        return SFSafariViewController(url: url)
    }
    
    func updateUIViewController(_ uiViewController: SFSafariViewController, context: Context) {
    }
}

/// Which local install server setup to use. Persisted via UserDefaults key
/// "installMethod" - SettingsView binds to it with @AppStorage, this file
/// reads it with UserDefaults directly (same split Feather uses between its
/// SwiftUI views and ServerInstaller for "Feather.serverMethod").
enum InstallMethod: Int, CaseIterable, Identifiable {
    case semiLocalHTTP = 0
    case localhostDirectSelfSigned = 1
    case localhostDirectPublicCA = 2

    var id: Int { rawValue }

    static var current: InstallMethod {
        InstallMethod(rawValue: UserDefaults.standard.integer(forKey: "installMethod")) ?? .semiLocalHTTP
    }

    var displayName: String {
        switch self {
        case .semiLocalHTTP: return "Semi Local (127.0.0.1)".localized
        case .localhostDirectSelfSigned: return "HTTPS (localhost.direct, self-signed)".localized
        case .localhostDirectPublicCA: return "HTTPS (localhost.direct, public CA)".localized
        }
    }

    var subtitle: String {
        switch self {
        case .semiLocalHTTP: return "No cert needed. Matches Feather's Semi Local + \"Only use localhost address\" - try this first.".localized
        case .localhostDirectSelfSigned: return "Real cert, immune to CA revocation, but requires a one-time profile install in Settings.".localized
        case .localhostDirectPublicCA: return "Real cert, no setup needed. May get revoked without warning - localhost.direct's own changelog shows this has happened before.".localized
        }
    }
}

func installAppVersion(appId: String, versionId: String, ipaTool: IPATool, recordsHistory: Bool) {
    let appData = AppData.shared
    
    setDowngradeProgress(0.02, detail: "Starting downgrade".localized)
    let path = ipaTool.downloadIPAForVersion(appId: appId, appVerId: versionId) { progress, detail in
        setDowngradeProgress(progress, detail: detail)
    }
    print("IPA downloaded to \(path)")
    setDowngradeProgress(0.92, detail: "Packing installable IPA".localized)
    
    let tempDir = FileManager.default.temporaryDirectory
    var contents = try! FileManager.default.contentsOfDirectory(atPath: path)
    print("Contents: \(contents)")
    // also delete this; i wanna see both the app's directory and the temp ipa GONE.
    let destinationUrl = tempDir.appendingPathComponent("app.ipa")
    try! Zip.zipFiles(paths: contents.map { URL(fileURLWithPath: path).appendingPathComponent($0) }, zipFilePath: destinationUrl, password: nil, progress: nil)
    print("IPA zipped to \(destinationUrl)")
    let path2 = URL(fileURLWithPath: path)
    var appDir = path2.appendingPathComponent("Payload")
    for file in try! FileManager.default.contentsOfDirectory(atPath: appDir.path) {
        if file.hasSuffix(".app") {
            print("Found app: \(file)")
            // i assume we delete this? idk how to though
            appDir = appDir.appendingPathComponent(file)
            break
        }
    }
    let infoPlistPath = appDir.appendingPathComponent("Info.plist")
    let infoPlist = NSDictionary(contentsOf: infoPlistPath)!
    let appBundleId = infoPlist["CFBundleIdentifier"] as! String
    let appVersion = infoPlist["CFBundleShortVersionString"] as! String
    print("appBundleId: \(appBundleId)")
    print("appVersion: \(appVersion)")

    appData.appBundleID = appBundleId
    appData.appVersion = appVersion
    setDowngradeProgress(0.95, detail: "Preparing install manifest".localized)
    
    if recordsHistory {
        let entry = DowngradeHistoryEntry(
            id: UUID(),
            appId: appId,
            appLink: appData.appLink,
            bundleId: appBundleId,
            installedVersion: appVersion,
            externalVersionId: versionId,
            date: Date(),
            keptAppData: DowngradeHistoryStore.keepsAppDataForNextInstall
        )
        DispatchQueue.main.async {
            appData.downgradeHistory = DowngradeHistoryStore.append(entry)
        }
    }
    
    DispatchQueue.global(qos: .background).async {
        do {
            // Refresh whichever cert store the selected method actually
            // needs (a no-op for Semi Local, and a no-op for either HTTPS
            // method if its pack is already fresh enough). Bounded wait so a
            // dead network doesn't hang the downgrade - we just fall back to
            // plain HTTP/127.0.0.1 if it times out.
            //
            // This has to happen here, off the main thread: installAppVersion
            // runs on the main thread up to this point (it's called directly
            // from UIAlertAction handlers), and update()'s completion hops
            // via DispatchQueue.main.async - blocking the main thread on this
            // semaphore before dispatching would deadlock that hop for the
            // full 10s timeout every time a refresh is actually needed.
            let method = InstallMethod.current
            let certSemaphore = DispatchSemaphore(value: 0)
            switch method {
            case .localhostDirectSelfSigned:
                LocalhostDirectManager.updateIfNeeded(for: .selfSigned) { _ in certSemaphore.signal() }
            case .localhostDirectPublicCA:
                LocalhostDirectManager.updateIfNeeded(for: .publicCA) { _ in certSemaphore.signal() }
            case .semiLocalHTTP:
                certSemaphore.signal()
            }
            _ = certSemaphore.wait(timeout: .now() + 10)

            // Figure out which cert (if any) backs this attempt. iOS requires
            // the OTA manifest fetch to be HTTPS with no way to click through
            // a warning, so without a trusted cert there's no way to
            // self-host the manifest; in that case (Semi Local, or an HTTPS
            // method whose cert isn't ready yet) we fall back to asking
            // api.palera.in to generate the manifest for us and point it at
            // our plain-HTTP local server on 127.0.0.1 - this is the same
            // thing Feather's "Semi Local" + "Only use localhost address"
            // does.
            let useHTTPS: Bool
            let host: String
            let certFileURL: URL?
            let keyFileURL: URL?
            switch method {
            case .localhostDirectSelfSigned where LocalhostDirectManager.hasCertificates(for: .selfSigned):
                useHTTPS = true
                host = LocalhostDirectManager.hostName
                certFileURL = LocalhostDirectManager.certificateURL(for: .selfSigned)
                keyFileURL = LocalhostDirectManager.privateKeyURL(for: .selfSigned)
            case .localhostDirectPublicCA where LocalhostDirectManager.hasCertificates(for: .publicCA):
                useHTTPS = true
                host = LocalhostDirectManager.hostName
                certFileURL = LocalhostDirectManager.certificateURL(for: .publicCA)
                keyFileURL = LocalhostDirectManager.privateKeyURL(for: .publicCA)
            default:
                useHTTPS = false
                host = "127.0.0.1"
                certFileURL = nil
                keyFileURL = nil
            }
            let scheme = useHTTPS ? "https" : "http"
            // Randomized per attempt (matches Feather) so a second downgrade in the
            // same session can never collide with a still-shutting-down previous
            // server on a fixed port.
            let port = Int.random(in: 4000...8000)


            let payloadURL = "\(scheme)://\(host):\(port)/signed.ipa"
            let finalURL: String = useHTTPS
                ? "\(scheme)://\(host):\(port)/manifest.plist"
                : "https://api.palera.in/genPlist?bundleid=\(appBundleId)&name=\(appBundleId)&version=\(appVersion)&fetchurl=\(payloadURL)"
            let installURL = "itms-services://?action=download-manifest&url=" + finalURL.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!

            // Apple's OTA install manifest format - see Feather's own ServerInstaller
            // for the same structure. Only the required fields are included; display
            // icons are optional and omitted here for simplicity, so the install
            // progress overlay will show a generic icon instead of the app's own.
            func makeInstallManifestData() -> Data {
                let manifest: [String: Any] = [
                    "items": [[
                        "assets": [[
                            "kind": "software-package",
                            "url": payloadURL,
                        ]],
                        "metadata": [
                            "bundle-identifier": appBundleId,
                            "bundle-version": appVersion,
                            "kind": "software",
                            "title": appBundleId,
                        ],
                    ]],
                ]
                return (try? PropertyListSerialization.data(
                    fromPropertyList: manifest,
                    format: .xml,
                    options: .zero
                )) ?? Data()
            }

            // Tear down whatever the previous downgrade attempt left running
            // before starting a fresh instance, so we don't leak a listening
            // server/thread for every downgrade done in one app session.
            InstallServerHolder.current?.shutdown()
            InstallServerHolder.current = nil

            let env = VaporEnvironment.shared
            let app = Application(env)
            InstallServerHolder.current = app

            if useHTTPS, let certFileURL, let keyFileURL {
                let certs = try NIOSSLCertificate.fromPEMFile(certFileURL.path)
                    .map { NIOSSLCertificateSource.certificate($0) }
                let key = try NIOSSLPrivateKey(file: keyFileURL.path, format: .pem)
                app.http.server.configuration.tlsConfiguration = try .makeServerConfiguration(
                    certificateChain: certs,
                    privateKey: .privateKey(key)
                )
                app.http.server.configuration.hostname = host
            }

            app.http.server.configuration.address = .hostname("0.0.0.0", port: port)
            app.http.server.configuration.port = port
            app.routes.defaultMaxBodySize = "512mb"

            app.get("*") { req -> Response in
                switch req.url.path {
                case "/manifest.plist":
                    print("Serving manifest.plist")
                    var headers = HTTPHeaders()
                    headers.add(name: .contentType, value: "text/xml")
                    return Response(status: .ok, headers: headers, body: .init(data: makeInstallManifestData()))

                case "/signed.ipa":
                    print("Serving signed.ipa")
                    let signedIPAData = try Data(contentsOf: destinationUrl)
                    return Response(status: .ok, body: .init(data: signedIPAData))

                case "/install":
                    print("Serving install page")
                    DispatchQueue.main.async {
                        appData.hasAppBeenServed = true
                        appData.applicationStatus = "Downgrade successful!".localized
                        appData.applicationIcon = "checkmark.circle.fill"
                        appData.applicationIconColor = .green
                        appData.downgradeProgress = 1
                        appData.downgradeProgressDetail = "Ready to install".localized
                        appData.showsDowngradeProgress = false
                    }
                    let installPage = """
                    <script type="text/javascript">
                        window.location = "\(installURL)"
                    </script>
                    """
                    var headers = HTTPHeaders()
                    headers.add(name: .contentType, value: "text/html")
                    return Response(status: .ok, headers: headers, body: .init(string: installPage))

                default:
                    return Response(status: .notFound)
                }
            }

            try app.server.start()
            print("Server has started listening on \(scheme)://\(host):\(port)")

            DispatchQueue.main.async {
                print("Requesting app install")

                // having it built-in no matter the version sounds more enjoyable, if you're already taking all the damn effort to do this bullshit then why not have this pop up on 17.x too?
                let safariView = SafariWebView(url: URL(string: "\(scheme)://\(host):\(port)/install")!)
                UIApplication.shared.windows.first?.rootViewController?.present(UIHostingController(rootView: safariView), animated: true, completion: nil)
            }
        } catch {
            print("Failed to start install server: \(error)")
            DispatchQueue.main.async {
                showAlert(title: "Error".localized, message: error.localizedDescription)
                resetDowngradeProgress()
            }
        }
    }
}

func downgradeAppToVersion(appId: String, versionId: String, ipaTool: IPATool) {
    installAppVersion(appId: appId, versionId: versionId, ipaTool: ipaTool, recordsHistory: true)
}

func restoreLatestAppVersion(appId: String, ipaTool: IPATool) {
    installAppVersion(appId: appId, versionId: "", ipaTool: ipaTool, recordsHistory: false)
}

func promptForVersionId(appId: String, versionIds: [String], ipaTool: IPATool) {
    let isiPad = UIDevice.current.userInterfaceIdiom == .pad
    let alert = UIAlertController(title: "Enter version ID".localized, message: "Select a version to downgrade to".localized, preferredStyle: isiPad ? .alert : .actionSheet)
    for versionId in versionIds {
        alert.addAction(UIAlertAction(title: versionId, style: .default, handler: { _ in
            setDowngradeProgress(0.01, detail: String(format: "Selected version %@".localized, versionId))
            downgradeAppToVersion(appId: appId, versionId: versionId, ipaTool: ipaTool)
        }))
    }
    alert.addAction(UIAlertAction(title: "Cancel".localized, style: .cancel, handler: { _ in
        resetDowngradeProgress()
    }))
    UIApplication.shared.windows.first?.rootViewController?.present(alert, animated: true, completion: nil)
}

func showAlert(title: String, message: String) {
    let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
    alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
    UIApplication.shared.windows.first?.rootViewController?.present(alert, animated: true, completion: nil)
}

func getAllAppVersionIdsFromServer(appId: String, ipaTool: IPATool) {
    let serverURL = "https://apis.bilin.eu.org/history/"
    let url = URL(string: "\(serverURL)\(appId)")!
    let request = URLRequest(url: url)
    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        if let error = error {
            DispatchQueue.main.async {
                showAlert(title: "Error".localized, message: error.localizedDescription)
                resetDowngradeProgress()
            }
            return
        }
        let json = try! JSONSerialization.jsonObject(with: data!) as! [String: Any]
        let versionIds = json["data"] as! [Dictionary<String, Any>]
        if versionIds.count == 0 {
            DispatchQueue.main.async {
                showAlert(title: "Error".localized, message: "No version IDs error".localized)
                resetDowngradeProgress()
            }
            return
        }
        DispatchQueue.main.async {
            let isiPad = UIDevice.current.userInterfaceIdiom == .pad
            let alert = UIAlertController(title: "Select a version".localized, message: "Select a version to downgrade to".localized, preferredStyle: isiPad ? .alert : .actionSheet)
            for versionId in versionIds {
                alert.addAction(UIAlertAction(title: "\(versionId["bundle_version"]!)", style: .default, handler: { _ in
                    let externalVersionId = "\(versionId["external_identifier"]!)"
                    setDowngradeProgress(0.01, detail: String(format: "Selected version %@".localized, "\(versionId["bundle_version"]!)"))
                    downgradeAppToVersion(appId: appId, versionId: externalVersionId, ipaTool: ipaTool)
                }))
            }
            alert.addAction(UIAlertAction(title: "Cancel".localized, style: .cancel, handler: { _ in
                resetDowngradeProgress()
            }))
            UIApplication.shared.windows.first?.rootViewController?.present(alert, animated: true, completion: nil)
        }
    }
    task.resume()
}

func downgradeApp(appId: String, ipaTool: IPATool) {
    let appData = AppData.shared
    
    setDowngradeProgress(0.01, detail: "Checking available versions".localized)
    let versionIds = ipaTool.getVersionIDList(appId: appId)
    if versionIds.isEmpty {
        print("No version ids were found, aborting...")
        DispatchQueue.main.async {
            Alertinator.shared.alert(title: "Failed to downgrade app!".localized, body: "Downgrade error description".localized)
            appData.isDowngrading = false
            appData.appLink = ""
            appData.applicationStatus = "Ready to Downgrade!".localized
            appData.applicationIcon = "checkmark.circle.fill"
            appData.showsDowngradeProgress = false
        }
        return
    }
    setDowngradeProgress(0.04, detail: "Choose a version".localized)
    
    let isiPad = UIDevice.current.userInterfaceIdiom == .pad
    
    let alert = UIAlertController(title: "Version ID".localized, message: "Manual or Server Description".localized, preferredStyle: isiPad ? .alert : .actionSheet)
    alert.addAction(UIAlertAction(title: "Manual".localized, style: .default, handler: { _ in
        promptForVersionId(appId: appId, versionIds: versionIds, ipaTool: ipaTool)
    }))
    alert.addAction(UIAlertAction(title: "Server".localized, style: .default, handler: { _ in
        getAllAppVersionIdsFromServer(appId: appId, ipaTool: ipaTool)
    }))
    alert.addAction(UIAlertAction(title: "Cancel".localized, style: .cancel, handler: { _ in
        resetDowngradeProgress()
    }))
    UIApplication.shared.windows.first?.rootViewController?.present(alert, animated: true, completion: nil)
}

func setDowngradeProgress(_ progress: Double, detail: String) {
    DispatchQueue.main.async {
        let appData = AppData.shared
        appData.downgradeProgress = min(max(progress, 0), 1)
        appData.downgradeProgressDetail = detail
        appData.showsDowngradeProgress = true
        appData.applicationStatus = detail
        appData.applicationIcon = "showMeProgressPlease"
        appData.applicationIconColor = .secondary
    }
}

func resetDowngradeProgress() {
    DispatchQueue.main.async {
        let appData = AppData.shared
        appData.isDowngrading = false
        appData.downgradeProgress = 0
        appData.downgradeProgressDetail = ""
        appData.showsDowngradeProgress = false
        appData.applicationStatus = "Ready to Downgrade!".localized
        appData.applicationIcon = "checkmark.circle.fill"
        appData.applicationIconColor = .secondary
    }
}

func cleanUp() {
    do {
        // first, delete the temporary ipa file.
        let tempDir = FileManager.default.temporaryDirectory
        let tempIPA = tempDir.appendingPathComponent("app.ipa")
        
        try FileManager.default.removeItem(at: tempIPA)
        // then, nuke the app directory.
        let docsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let appFolder = docsURL.appendingPathComponent("app")
        
        try FileManager.default.removeItem(at: appFolder)
    } catch {
        
    }
}

/// Separate from InstallServerHolder so tapping "Install Trust Profile" in
/// Settings can never race with/tear down an in-progress downgrade's server.
private final class UtilityServerHolder {
    static var current: Application?
}

/// Fetches the localhost.direct cert if needed, then hands the trust
/// profile to Safari so iOS's native "Install Profile" flow kicks in.
/// Directly opening a local file doesn't reliably trigger that flow - Safari
/// downloading something with Content-Type: application/x-apple-aspen-config
/// is the well-documented, reliable way to do it (the same mechanism MDM
/// enrollment pages and tools like Charles Proxy/mitmproxy use), so this
/// spins up a tiny loopback-only HTTP server just to serve it. Plain HTTP
/// and 127.0.0.1 are both fine here since this is a manual, one-time setup
/// step done locally, not part of the cellular-install path.
func presentLocalhostDirectTrustProfile(completion: @escaping (Bool) -> Void) {
    LocalhostDirectManager.updateIfNeeded(for: .selfSigned) { success in
        guard success, let profileData = LocalhostDirectManager.makeTrustProfileData() else {
            completion(false)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            UtilityServerHolder.current?.shutdown()
            UtilityServerHolder.current = nil

            let app = Application(VaporEnvironment.shared)
            UtilityServerHolder.current = app
            let port = Int.random(in: 4000...8000)
            app.http.server.configuration.address = .hostname("127.0.0.1", port: port)
            app.http.server.configuration.port = port

            app.get("localhostdirect.mobileconfig") { _ -> Response in
                var headers = HTTPHeaders()
                headers.add(name: .contentType, value: "application/x-apple-aspen-config")
                return Response(status: .ok, headers: headers, body: .init(data: profileData))
            }

            do {
                try app.server.start()
                DispatchQueue.main.async {
                    let url = URL(string: "http://127.0.0.1:\(port)/localhostdirect.mobileconfig")!
                    let safariView = SafariWebView(url: url)
                    UIApplication.shared.windows.first?.rootViewController?.present(UIHostingController(rootView: safariView), animated: true, completion: nil)
                    completion(true)
                }
            } catch {
                print("Failed to start trust profile server: \(error)")
                DispatchQueue.main.async { completion(false) }
            }
        }
    }
}
