//
//  AuthTransferManager.swift
//  WaffleStore
//
//  Lets a user move their saved Apple ID session between forks (or from an
//  old install to a fresh one) without retyping their password/2FA code
//  every time.
//
//  WHAT THIS DOES *NOT* SOLVE: the reason logging into one fork logs you out
//  of another isn't a local-storage thing at all, so import/export can't fix
//  it. StoreClient.generateGuid() (see IPATool.swift) computes a "device"
//  GUID purely from a SHA1 hash of the Apple ID string - zero device-specific
//  entropy, no randomness, nothing tied to this install or this hardware.
//  Every fork that hasn't touched that function computes the *identical*
//  GUID for the same Apple ID. Apple's servers have no way to tell "two
//  different apps on one phone" apart from "the same client logging in
//  again" when that's the only identifying signal being sent - so a fresh
//  login in one fork appears to invalidate whatever session another fork
//  was holding for that GUID. Worth knowing too: IPATool.authenticate()
//  (line ~404) only checks whether a local authinfo file exists before
//  deciding it's still logged in - it never actually validates the session
//  against Apple first. So the "other" app doesn't even notice its session
//  died until a real request fails.
//
//  What this DOES do: saves you from retyping credentials when you
//  deliberately switch which fork you're using, or when reinstalling.
//
//  SECURITY NOTE - read this before wiring up a "Share" button on the export:
//  the on-device authinfo blob (see EncryptedKeychainWrapper in
//  IPATool.swift) includes the account's actual plaintext Apple ID password,
//  kept alongside the session cookies specifically so a stale session can
//  silently re-authenticate. That's fine at rest - it's encrypted with a
//  device-only Secure Enclave key that can't be extracted or leave the
//  device. The moment you export it to a portable file, that protection is
//  gone unless we add our own, so exports here are re-encrypted with a
//  passphrase the user chooses (AES-GCM, key derived via HKDF). Be upfront
//  with the user that this is a real limitation, not a formality: HKDF is
//  built for high-entropy input like a Diffie-Hellman secret, not a
//  human-chosen passphrase - it doesn't add the deliberate slowness a
//  password-specific KDF (PBKDF2/scrypt/Argon2) would to resist brute-forcing
//  a short or reused passphrase. A proper password KDF would need
//  CommonCrypto bridging or a third-party dependency neither of which felt
//  worth the added build risk for this. Net effect: this exported file is
//  only as safe as the passphrase protecting it and where the file ends up -
//  tell users to treat both like their actual Apple ID password, because
//  functionally, they are.
//

import Foundation
import CryptoKit
import Security

enum AuthTransferManager {
    private struct Envelope: Codable {
        let version: Int
        let salt: String       // base64
        let nonce: String      // base64
        let ciphertext: String // base64, ciphertext + GCM tag concatenated
    }

    private static func derivedKey(passphrase: String, salt: Data) -> SymmetricKey {
        let inputKey = SymmetricKey(data: Data(passphrase.utf8))
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: Data("VioletStore-authinfo-export".utf8),
            outputByteCount: 32
        )
    }

    /// Encrypts the currently-saved auth info with the given passphrase and
    /// writes it to a temp file ready to hand to presentShareSheet(with:).
    /// Returns nil if there's nothing saved to export yet, or on any
    /// crypto/file error.
    static func exportToFile(passphrase: String) -> URL? {
        guard !passphrase.isEmpty, let base64 = EncryptedKeychainWrapper.loadAuthInfo() else {
            print("No auth info to export, or empty passphrase")
            return nil
        }

        var salt = Data(count: 16)
        let saltResult = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard saltResult == errSecSuccess else {
            print("Failed to generate random salt")
            return nil
        }

        let key = derivedKey(passphrase: passphrase, salt: salt)
        guard let plaintext = base64.data(using: .utf8) else { return nil }

        guard let sealed = try? AES.GCM.seal(plaintext, using: key) else {
            print("Failed to encrypt auth info for export")
            return nil
        }

        let envelope = Envelope(
            version: 1,
            salt: salt.base64EncodedString(),
            nonce: Data(sealed.nonce).base64EncodedString(),
            ciphertext: (sealed.ciphertext + sealed.tag).base64EncodedString()
        )

        guard let envelopeData = try? JSONEncoder().encode(envelope) else { return nil }

        // .json extension so it matches the same UTType.json fileImporter
        // filter used for downgrade-history import/export elsewhere in
        // Settings - the envelope really is JSON, just an encrypted blob
        // inside it.
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("VioletStore-login-export.json")
        do {
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.removeItem(at: url)
            }
            try envelopeData.write(to: url, options: .atomic)
            return url
        } catch {
            print("Failed to write auth export file: \(error)")
            return nil
        }
    }

    /// Decrypts an exported file's contents with the given passphrase and
    /// saves it as this app's own local auth info, re-encrypted with this
    /// app's own device-local key - same end state as if you'd just logged
    /// in normally. Returns false on a wrong passphrase or a corrupt file.
    static func importFromData(_ envelopeData: Data, passphrase: String) -> Bool {
        guard
            let envelope = try? JSONDecoder().decode(Envelope.self, from: envelopeData),
            let salt = Data(base64Encoded: envelope.salt),
            let nonceData = Data(base64Encoded: envelope.nonce),
            let combined = Data(base64Encoded: envelope.ciphertext),
            combined.count > 16
        else {
            print("Auth export file is corrupt or unreadable")
            return false
        }

        let tag = combined.suffix(16)
        let ciphertext = combined.dropLast(16)

        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            let key = derivedKey(passphrase: passphrase, salt: salt)
            // AES-GCM verifies the auth tag as part of open() - a wrong
            // passphrase throws here rather than silently producing garbage.
            let plaintext = try AES.GCM.open(sealedBox, using: key)
            guard let base64 = String(data: plaintext, encoding: .utf8) else { return false }

            // Belt-and-suspenders sanity check that it's actually a real
            // auth blob before committing it as our own login.
            guard
                let jsonData = Data(base64Encoded: base64),
                (try? JSONSerialization.jsonObject(with: jsonData, options: [])) as? [String: Any] != nil
            else {
                return false
            }

            EncryptedKeychainWrapper.saveAuthInfo(base64: base64)
            return true
        } catch {
            print("Failed to decrypt/import auth info (likely wrong passphrase): \(error)")
            return false
        }
    }

    /// Convenience wrapper for callers that still have an on-disk URL and
    /// haven't read it yet. Prefer reading the file yourself (inside your
    /// own startAccessingSecurityScopedResource block, if it came from a
    /// fileImporter) and calling importFromData(_:passphrase:) directly if
    /// you need to defer the passphrase prompt to a later step - security-
    /// scoped access isn't guaranteed to still be valid by then.
    static func importFromFile(at url: URL, passphrase: String) -> Bool {
        guard let envelopeData = try? Data(contentsOf: url) else {
            print("Couldn't read auth export file")
            return false
        }
        return importFromData(envelopeData, passphrase: passphrase)
    }
}
