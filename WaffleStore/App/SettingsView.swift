import SwiftUI
import PartyUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject var appData: AppData
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    
    @AppStorage("autoCleanApp") var autoCleanApp: Bool = true
    @AppStorage("installMethod") private var installMethodRaw: Int = InstallMethod.semiLocalHTTP.rawValue
    @StateObject private var localizationManager = LocalizationManager.shared
    @State private var showFileImporter = false
    @State private var isUpdatingCertificates = false
    @State private var isInstallingTrustProfile = false

    @State private var showExportLoginPrompt = false
    @State private var exportLoginPassphrase = ""
    @State private var showImportLoginFileImporter = false
    @State private var showImportLoginPrompt = false
    @State private var importLoginPassphrase = ""
    @State private var pendingImportLoginData: Data?

    private var installMethod: InstallMethod {
        InstallMethod(rawValue: installMethodRaw) ?? .semiLocalHTTP
    }
    
    private var appVersionString: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(version) (\(build))"
    }
    
    var body: some View {
        NavigationStack {
            List {
                Section(header: HeaderLabel(text: "About".localized, icon: "info.circle")) {
                    VStack(alignment: .leading, spacing: 10) {
                        AppInfoCell()
                        Button(action: {
                            openURL(URL(string: "https://github.com/username252510/VioletStore")!)
                        }) {
                            ButtonLabel(text: "GitHub".localized, icon: "github", useImage: true)
                        }
                        .buttonStyle(TranslucentButtonStyle(color: .github))
                        Button(action: {
                            openURL(URL(string: "https://violetstore.c0n.xyz")!)
                        }) {
                            ButtonLabel(text: "Website".localized, icon: "globe")
                        }
                        .buttonStyle(TranslucentButtonStyle())
                    }
                }
                
                Section(header: HeaderLabel(text: "Settings".localized, icon: "gearshape")) {
                    Toggle(isOn: $autoCleanApp) {
                        Text("Auto-Clean App".localized)
                        Text("Auto-Clean Description".localized)
                    }
                }

                Section(
                    header: HeaderLabel(text: "Server & SSL".localized, icon: "server.rack"),
                    footer: Text(installMethod.subtitle)
                ) {
                    Picker(selection: $installMethodRaw) {
                        ForEach(InstallMethod.allCases) { method in
                            Text(method.displayName).tag(method.rawValue)
                        }
                    } label: {
                        Text("Install Method".localized)
                    }
                    .pickerStyle(.menu)

                    if installMethod == .localhostDirectSelfSigned {
                        Button(action: {
                            isUpdatingCertificates = true
                            LocalhostDirectManager.update(for: .selfSigned) { success in
                                isUpdatingCertificates = false
                                showAlert(
                                    title: "localhost.direct".localized,
                                    message: success
                                        ? "Certificate downloaded. Now tap \"Install Trust Profile\" below and follow the steps.".localized
                                        : "Failed to download, check your internet connection and try again.".localized
                                )
                            }
                        }) {
                            ButtonLabel(text: "Download Certificate".localized, icon: "arrow.down.doc")
                        }
                        .buttonStyle(TranslucentButtonStyle())
                        .disabled(isUpdatingCertificates)

                        Button(action: {
                            isInstallingTrustProfile = true
                            presentLocalhostDirectTrustProfile { success in
                                isInstallingTrustProfile = false
                                if !success {
                                    showAlert(
                                        title: "localhost.direct".localized,
                                        message: "Couldn't prepare the trust profile. Try downloading the certificate above first.".localized
                                    )
                                }
                            }
                        }) {
                            ButtonLabel(text: "Install Trust Profile".localized, icon: "checkmark.seal")
                        }
                        .buttonStyle(TranslucentButtonStyle())
                        .disabled(isInstallingTrustProfile)

                        Text("One-time step: after installing the profile, go to Settings > General > About > Certificate Trust Settings and enable full trust for \"localhost.direct\".".localized)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    if installMethod == .localhostDirectPublicCA {
                        Button(action: {
                            isUpdatingCertificates = true
                            LocalhostDirectManager.update(for: .publicCA) { success in
                                isUpdatingCertificates = false
                                showAlert(
                                    title: "localhost.direct".localized,
                                    message: success
                                        ? "Certificate downloaded.".localized
                                        : "Failed to download, check your internet connection and try again.".localized
                                )
                            }
                        }) {
                            ButtonLabel(text: "Download Certificate".localized, icon: "arrow.down.doc")
                        }
                        .buttonStyle(TranslucentButtonStyle())
                        .disabled(isUpdatingCertificates)
                    }
                }

                Section(
                    header: HeaderLabel(text: "Login Transfer".localized, icon: "person.badge.key"),
                    footer: Text("Logging into another fork with the same Apple ID will still sign you out here - that's on Apple's end, not something this can fix. This only saves you from retyping your password and 2FA code. The exported file is only as safe as the passphrase you set - treat both like your actual Apple ID password.".localized)
                ) {
                    Button(action: {
                        exportLoginPassphrase = ""
                        showExportLoginPrompt = true
                    }) {
                        ButtonLabel(text: "Export Login".localized, icon: "square.and.arrow.up")
                    }
                    .buttonStyle(TranslucentButtonStyle())
                    .disabled(!EncryptedKeychainWrapper.hasAuthInfo())

                    Button(action: {
                        showImportLoginFileImporter = true
                    }) {
                        ButtonLabel(text: "Import Login".localized, icon: "square.and.arrow.down")
                    }
                    .buttonStyle(TranslucentButtonStyle())
                }
                .alert("Set an Export Passphrase".localized, isPresented: $showExportLoginPrompt) {
                    SecureField("Passphrase".localized, text: $exportLoginPassphrase)
                    Button("Export".localized) {
                        if let url = AuthTransferManager.exportToFile(passphrase: exportLoginPassphrase) {
                            presentShareSheet(with: url)
                        } else {
                            showAlert(
                                title: "Login Transfer".localized,
                                message: "Couldn't export. Make sure you're logged in and entered a passphrase.".localized
                            )
                        }
                        exportLoginPassphrase = ""
                    }
                    Button("Cancel".localized, role: .cancel) {
                        exportLoginPassphrase = ""
                    }
                } message: {
                    Text("This file will contain your Apple ID password. Choose a real, strong passphrase - anyone with both the file and this passphrase can decrypt it.".localized)
                }
                .fileImporter(isPresented: $showImportLoginFileImporter, allowedContentTypes: [.json]) { result in
                    switch result {
                    case .success(let url):
                        if url.startAccessingSecurityScopedResource() {
                            defer { url.stopAccessingSecurityScopedResource() }
                            pendingImportLoginData = try? Data(contentsOf: url)
                        }
                        if pendingImportLoginData != nil {
                            importLoginPassphrase = ""
                            showImportLoginPrompt = true
                        } else {
                            showAlert(title: "Login Transfer".localized, message: "Couldn't read that file.".localized)
                        }
                    case .failure(let error):
                        print("Failed to import login: \(error)")
                    }
                }
                .alert("Enter the Export Passphrase".localized, isPresented: $showImportLoginPrompt) {
                    SecureField("Passphrase".localized, text: $importLoginPassphrase)
                    Button("Import".localized) {
                        if let data = pendingImportLoginData,
                           AuthTransferManager.importFromData(data, passphrase: importLoginPassphrase) {
                            showAlert(title: "Login Transfer".localized, message: "Login imported successfully.".localized)
                        } else {
                            showAlert(
                                title: "Login Transfer".localized,
                                message: "Couldn't import - wrong passphrase, or the file wasn't a valid export.".localized
                            )
                        }
                        importLoginPassphrase = ""
                        pendingImportLoginData = nil
                    }
                    Button("Cancel".localized, role: .cancel) {
                        importLoginPassphrase = ""
                        pendingImportLoginData = nil
                    }
                }
                
                Section(header: HeaderLabel(text: "Language".localized, icon: "globe"), footer:
                    Button(action: {
                        openURL(URL(string: "https://poeditor.com/join/project/Ofr2qvyudt")!)
                    }) {
                        Text("Translation Thank You".localized)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                ) {
                    Picker("Language".localized, selection: $localizationManager.currentLanguage) {
                        ForEach(Language.allCases) { language in
                            Text(language.displayName).tag(language)
                        }
                    }
                    .pickerStyle(.menu)
                }
                
                Section(header: HeaderLabel(text: "Data".localized, icon: "loupe"), footer: Text("Storage Warning".localized)) {
                    VStack {
                        Button(action: {
                            let tempDir = FileManager.default.temporaryDirectory
                            let tempIPAURL = tempDir.appendingPathComponent("app.ipa")
                            presentShareSheet(with: tempIPAURL)
                        }) {
                            ButtonLabel(text: "Export IPA".localized, icon: "arrow.up.doc")
                        }
                        .buttonStyle(TranslucentButtonStyle())
                        .disabled(!appData.hasAppBeenServed)
                        Button(action: {
                            cleanUp()
                        }) {
                            ButtonLabel(text: "Clean Documents".localized, icon: "trash")
                        }
                        .buttonStyle(TranslucentButtonStyle())
                        
                        HStack {
                            Button(action: {
                                if let url = DowngradeHistoryStore.exportToJSON() {
                                    presentShareSheet(with: url)
                                }
                            }) {
                                ButtonLabel(text: "Export History".localized, icon: "square.and.arrow.up")
                            }
                            .buttonStyle(TranslucentButtonStyle())
                            
                            Button(action: {
                                showFileImporter = true
                            }) {
                                ButtonLabel(text: "Import History".localized, icon: "square.and.arrow.down")
                            }
                            .buttonStyle(TranslucentButtonStyle())
                        }
                    }
                }
                .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [.json]) { result in
                    switch result {
                    case .success(let url):
                        if url.startAccessingSecurityScopedResource() {
                            defer { url.stopAccessingSecurityScopedResource() }
                            if let importedHistory = DowngradeHistoryStore.importFromJSON(at: url) {
                                appData.downgradeHistory = importedHistory
                            }
                        }
                    case .failure(let error):
                        print("Failed to import history: \(error)")
                    }
                }
                Section(header: HeaderLabel(text: "Credits".localized, icon: "star")) {
                    LinkCreditCell(image: Image("mineek"), name: "mineek", description: "Original creator of MuffinStore Jailed.".localized, url: "https://github.com/mineek")
                    LinkCreditCell(image: Image("lunginspector"), name: "lunginspector", description: "Original creator of PancakeStore.".localized, url: "https://github.com/lunginspector")
                    LinkCreditCell(image: Image("skadz"), name: "skadz", description: "Original creator of PancakeStore.".localized, url: "https://github.com/skadz108")
                    LinkCreditCell(image: Image("nxtcoreee3"), name: "nxtcoreee3", description: "UI changes and feature improvements with WaffleStore".localized, url: "https://github.com/nxtcoreee3")
                    LinkCreditCell(image: Image("Con"), name: "Con (username252510)", description: "Installation and other QoL feature improvements".localized, url: "https://github.com/username252510")
                }
            }
            .navigationTitle("Settings".localized)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(action: {
                        dismiss()
                    }) {
                        Image(systemName: "xmark")
                    }
                }
            }
        }
    }
}
