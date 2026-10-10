// The CryptoKit half of the Kotlin/Native CryptoProvider (macosMain, AppleCryptoProvider):
// the two AEADs and X25519, exposed as C functions for cinterop (see lep_cryptokit.h).
//
// Every function returns 0 on success, LEP_CK_AUTH_FAILED when an AEAD tag does not verify, and
// LEP_CK_FAILED for anything else CryptoKit refuses. The Kotlin caller checks sizes first, because
// a few CryptoKit initialisers stop the process on a bad size rather than throwing, and a daemon
// must turn bad input into an error, never into a crash.

import CryptoKit
import Foundation

private let ok: Int32 = 0
private let failed: Int32 = 1
private let authFailed: Int32 = 2

private func bytes(_ pointer: UnsafePointer<UInt8>?, _ count: Int) -> Data {
    guard let pointer, count > 0 else { return Data() }
    return Data(bytes: pointer, count: count)
}

private func write<D: DataProtocol>(_ data: D, to out: UnsafeMutablePointer<UInt8>?) {
    guard let out else { return }
    var offset = 0
    for region in data.regions {
        region.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            (out + offset).update(from: base, count: raw.count)
            offset += raw.count
        }
    }
}

// ── AEADs ──────────────────────────────────────────────────────────────────────────────────

/// AES-GCM seal: `out` receives ciphertext || 16-byte tag (ptlen + 16 bytes).
@_cdecl("lep_ck_aes_gcm_seal")
public func lep_ck_aes_gcm_seal(
    _ key: UnsafePointer<UInt8>?, _ keyLength: Int,
    _ nonce: UnsafePointer<UInt8>?, _ nonceLength: Int,
    _ plaintext: UnsafePointer<UInt8>?, _ plaintextLength: Int,
    _ aad: UnsafePointer<UInt8>?, _ aadLength: Int,
    _ out: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    do {
        let box = try AES.GCM.seal(
            bytes(plaintext, plaintextLength),
            using: SymmetricKey(data: bytes(key, keyLength)),
            nonce: try AES.GCM.Nonce(data: bytes(nonce, nonceLength)),
            authenticating: bytes(aad, aadLength)
        )
        write(box.ciphertext, to: out)
        write(box.tag, to: out.map { $0 + plaintextLength })
        return ok
    } catch {
        return failed
    }
}

/// AES-GCM open of ciphertext || 16-byte tag: `out` receives the plaintext (length - 16 bytes).
@_cdecl("lep_ck_aes_gcm_open")
public func lep_ck_aes_gcm_open(
    _ key: UnsafePointer<UInt8>?, _ keyLength: Int,
    _ nonce: UnsafePointer<UInt8>?, _ nonceLength: Int,
    _ sealed: UnsafePointer<UInt8>?, _ sealedLength: Int,
    _ aad: UnsafePointer<UInt8>?, _ aadLength: Int,
    _ out: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    guard sealedLength >= 16 else { return authFailed }
    let all = bytes(sealed, sealedLength)
    do {
        let box = try AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: bytes(nonce, nonceLength)),
            ciphertext: all.prefix(sealedLength - 16),
            tag: all.suffix(16)
        )
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(box, using: SymmetricKey(data: bytes(key, keyLength)),
                                         authenticating: bytes(aad, aadLength))
        } catch {
            return authFailed
        }
        write(plaintext, to: out)
        return ok
    } catch {
        return failed
    }
}

/// ChaCha20-Poly1305 (RFC 8439) seal: `out` receives ciphertext || 16-byte tag.
@_cdecl("lep_ck_chachapoly_seal")
public func lep_ck_chachapoly_seal(
    _ key: UnsafePointer<UInt8>?, _ keyLength: Int,
    _ nonce: UnsafePointer<UInt8>?, _ nonceLength: Int,
    _ plaintext: UnsafePointer<UInt8>?, _ plaintextLength: Int,
    _ aad: UnsafePointer<UInt8>?, _ aadLength: Int,
    _ out: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    do {
        let box = try ChaChaPoly.seal(
            bytes(plaintext, plaintextLength),
            using: SymmetricKey(data: bytes(key, keyLength)),
            nonce: try ChaChaPoly.Nonce(data: bytes(nonce, nonceLength)),
            authenticating: bytes(aad, aadLength)
        )
        write(box.ciphertext, to: out)
        write(box.tag, to: out.map { $0 + plaintextLength })
        return ok
    } catch {
        return failed
    }
}

/// ChaCha20-Poly1305 open of ciphertext || 16-byte tag: `out` receives the plaintext.
@_cdecl("lep_ck_chachapoly_open")
public func lep_ck_chachapoly_open(
    _ key: UnsafePointer<UInt8>?, _ keyLength: Int,
    _ nonce: UnsafePointer<UInt8>?, _ nonceLength: Int,
    _ sealed: UnsafePointer<UInt8>?, _ sealedLength: Int,
    _ aad: UnsafePointer<UInt8>?, _ aadLength: Int,
    _ out: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    guard sealedLength >= 16 else { return authFailed }
    let all = bytes(sealed, sealedLength)
    do {
        let box = try ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: bytes(nonce, nonceLength)),
            ciphertext: all.prefix(sealedLength - 16),
            tag: all.suffix(16)
        )
        let plaintext: Data
        do {
            plaintext = try ChaChaPoly.open(box, using: SymmetricKey(data: bytes(key, keyLength)),
                                            authenticating: bytes(aad, aadLength))
        } catch {
            return authFailed
        }
        write(plaintext, to: out)
        return ok
    } catch {
        return failed
    }
}

// ── X25519 ─────────────────────────────────────────────────────────────────────────────────

/// The X25519 public key (32 bytes) for a 32-byte scalar.
@_cdecl("lep_ck_x25519_public_key")
public func lep_ck_x25519_public_key(
    _ privateKey: UnsafePointer<UInt8>?, _ out: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    do {
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes(privateKey, 32))
        write(key.publicKey.rawRepresentation, to: out)
        return ok
    } catch {
        return failed
    }
}

/// X25519(privateKey, peerPublicKey): the raw 32-byte shared secret.
@_cdecl("lep_ck_x25519")
public func lep_ck_x25519(
    _ privateKey: UnsafePointer<UInt8>?, _ peerPublicKey: UnsafePointer<UInt8>?,
    _ out: UnsafeMutablePointer<UInt8>?
) -> Int32 {
    do {
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes(privateKey, 32))
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: bytes(peerPublicKey, 32))
        let secret = try key.sharedSecretFromKeyAgreement(with: peer)
        secret.withUnsafeBytes { raw in write(Data(raw), to: out) }
        return ok
    } catch {
        return failed
    }
}
