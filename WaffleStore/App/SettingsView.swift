import SwiftUI
import PartyUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject var appData: AppData
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    
    @AppStorage("autoCleanApp") var autoCleanApp: Bool = true
    @StateObject private var localizationManager = LocalizationManager.shared
    @State private var showFileImporter = false
    @State private var isUpdatingCertificates = false
    
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
                    footer: Text("Server SSL Description".localized)
                ) {
                    Button(action: {
                        isUpdatingCertificates = true
                        SSLCertificateManager.update { success in
                            isUpdatingCertificates = false
                            if success {
                                showAlert(
                                    title: "SSL Certificates".localized,
                                    message: "Certificates updated successfully.".localized
                                )
                            } else {
                                showAlert(
                                    title: "SSL Certificates".localized,
                                    message: "Failed to download, check your internet connection and try again.".localized
                                )
                            }
                        }
                    }) {
                        ButtonLabel(text: "Update SSL Certificates".localized, icon: "arrow.down.doc")
                    }
                    .buttonStyle(TranslucentButtonStyle())
                    .disabled(isUpdatingCertificates)
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
