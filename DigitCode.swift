//
//  DigitCode.swift
//  Firebase
//
//  Created by Daniel Vebman on 7/21/17.
//  Copyright © 2017 Brinklet. All rights reserved.
//

/*
    IMPORTANT:
    Be sure to include a bridging header with the following line in it:
    #import <CommonCrypto/CommonHMAC.h>
*/

import Foundation

/// A class that manages getting `hotp` and `totp` tokens given an `RFC 4648` compliant `secret`.
class DigitCode: NSObject {
    
    /** 
    Called every 30 seconds to indicate a new totp code. Will be called a fraction of a second late.
    
    Delegate should only be used when a `totpToken` is desired.
    
    Delegate method `totpTokenDidChange(code:)` is called immediately after `delegate` is set.
    */
    var delegate: DigitCodeDelegate? {
        didSet {
            syncTimer()
        }
    }
    
    /// A 16 byte, RFC 4648 compliant string, which should be kept secret.
    private(set) var secret = ""
    
    /** Initialize a `DigitCode` object with an `RFC 4648` compliant, 16 byte secret.
    - Parameter secret: an `RFC 4648` compliant, 16 byte secret. If `secret` is invalid, `self` will be equal to `nil`, and an error will be printed to the console. `String.is16RFC4648Compliant` property can be used to determine if this error will occur in advance.
    */
    init?(secret: String) {
        if secret.is16RFC4648Complaint {
            self.secret = secret
        } else {
            print("***", "Error: Secret is not RFC 4648 compliant, so tokens cannot be generated!")
            return nil
        }
    }
    
    /**
     Returns a 6-digit array representing the token given `secret` and `intervals`.
     - Parameter intervals: the number of intervals passed.
    */
    func getHotpToken(intervals: Int) -> [Int]? {
        guard let keyData = Base32Decode(data: secret) else { return nil }
        
        var packedIntervalsArray = pack(intervals.bigEndian, byteOrder: ByteOrder.bigEndian)
        packedIntervalsArray.reverse()
        for _ in 0 ..< (8 - packedIntervalsArray.count) {
            packedIntervalsArray.insert(0, at: 0)
        }
        let messageData = Data(bytes: packedIntervalsArray)
        
        let hash = hmac(key: keyData, data: messageData)
        
        var truncatedHash = hash.withUnsafeBytes { (pointer: UnsafePointer<UInt8>) -> UInt32 in
            let offset = hash[19] & 15
            let truncatedHashPointer = pointer + Int(offset)
            return truncatedHashPointer.withMemoryRebound(to: UInt32.self, capacity: 1) {
                $0.pointee
            }
        }
        
        truncatedHash = UInt32(bigEndian: truncatedHash)
        truncatedHash &= 0x7fffffff
        truncatedHash = truncatedHash % UInt32(1000000)
        let truncatedHashStr = String(truncatedHash).padding(toLength: 6, withPad: "0", startingAt: 0)
        let tokenArray = truncatedHashStr.characters.flatMap { Int(String($0)) ?? 0 }
        return tokenArray
    }
    
    /// The 6-digit array representing the token given `secret` and the current time.
    var totpToken: [Int]? {
        return totpToken(at: Date())
    }
    
    /**
     The 6-digit array representing the token given `secret` and a date.
     - Parameter date: the date for which the totp token is requested.
    */
    func totpToken(at date: Date) -> [Int]? {
        return getHotpToken(intervals: Int(floor(date.timeIntervalSince1970 / 30)))
    }
    
    /// Syncs and then starts the timer to be just behind the true 30 second time cycle.
    private func syncTimer() {
        if totpToken != nil { delegate?.totpTokenDidChange(code: totpToken!) }
        let wait = 30 - (Date().timeIntervalSince1970).truncatingRemainder(dividingBy: 30) + 0.5
        Timer.scheduledTimer(withTimeInterval: wait, repeats: false) { (_) in
            self.startTimer()
        }
    }
    
    /// Starts the timer for calling `delegate` method `totpTokenDidChange(code:)` every 30 seconds.
    private func startTimer() {
        if totpToken != nil { delegate?.totpTokenDidChange(code: totpToken!) }
        Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { (_) in
            if self.totpToken != nil { self.delegate?.totpTokenDidChange(code: self.totpToken!) }
        }
    }
    
    /// Uses `HMAC` to create a hash given a `key` and `data`.
    private func hmac(key: Data, data: Data) -> Data {
        let hashLength = Int(CC_SHA1_DIGEST_LENGTH)
        let macOut = UnsafeMutablePointer<UInt8>.allocate(capacity: hashLength)
        defer { macOut.deallocate(capacity: hashLength) }
        
        key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), keyBytes, key.count, dataBytes, data.count, macOut)
            }
        }
        
        return Data(bytes: macOut, count: hashLength)
    }
    
    private enum ByteOrder {
        case bigEndian
        case littleEndian
        static let nativeByteOrder: ByteOrder = (Int(CFByteOrderGetCurrent()) == Int(CFByteOrderLittleEndian.rawValue)) ? .littleEndian : .bigEndian
    }
    
    /// Packs a value, optionally taking a `ByteOrder`.
    private func pack<T: Any>( _ value: T, byteOrder: ByteOrder = .nativeByteOrder) -> [UInt8] {
        var value = value
        let valueByteArray = withUnsafePointer(to: &value) {
            Array(UnsafeBufferPointer(start: $0.withMemoryRebound(to: UInt8.self, capacity: 1){$0}, count: MemoryLayout<T>.size))
        }
        return (byteOrder == .littleEndian) ? valueByteArray : valueByteArray.reversed()
    }
    
    /// Decodes a base 32, `RFC 4648` compliant string.
    private func Base32Decode(data: String) -> Data? {
        let characters = [ "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "2", "3", "4", "5", "6", "7"]
        let __ = 255
        let alphabet = [
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x00 - 0x0F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x10 - 0x1F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x20 - 0x2F
            __,__,26,27, 28,29,30,31, __,__,__,__, __, 0,__,__,  // 0x30 - 0x3F
            __, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,  // 0x40 - 0x4F
            15,16,17,18, 19,20,21,22, 23,24,25,__, __,__,__,__,  // 0x50 - 0x5F
            __, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,  // 0x60 - 0x6F
            15,16,17,18, 19,20,21,22, 23,24,25,__, __,__,__,__,  // 0x70 - 0x7F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x80 - 0x8F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0x90 - 0x9F
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xA0 - 0xAF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xB0 - 0xBF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xC0 - 0xCF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xD0 - 0xDF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xE0 - 0xEF
            __,__,__,__, __,__,__,__, __,__,__,__, __,__,__,__,  // 0xF0 - 0xFF
        ]
        return Base32Decode(data: data, alphabet: alphabet, characters: characters)
    }
    
    /// Decodes a base 32, `RFC 4648` compliant string given an `alphabet` and `characters`.
    private func Base32Decode(data: String, alphabet: Array<Int>, characters: Array<String>) -> Data? {
        var processingData = ""
        
        for char in data.uppercased().characters {
            let str = String(char)
            
            if characters.contains(str) {
                processingData += str
            } else if !characters.contains(str) && str != "=" {
                return nil
            }
        }
        
        if let base32Data = processingData.data(using: String.Encoding.ascii, allowLossyConversion: false) {
            let fullGroups = base32Data.count / 8
            var bytesInPartialGroup: Int = 0
            switch base32Data.count % 8 {
            case 0:
                bytesInPartialGroup = 0
            case 2:
                bytesInPartialGroup = 1
            case 4:
                bytesInPartialGroup = 2
            case 5:
                bytesInPartialGroup = 3
            case 7:
                bytesInPartialGroup = 4
            default:
                return nil
            }
            let totalNumberOfBytes = fullGroups * 5 + bytesInPartialGroup
            
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: totalNumberOfBytes)
            
            var base32Bytes = [UInt8](repeating: 0, count: base32Data.count)
            base32Data.copyBytes(to: &base32Bytes, count: base32Bytes.count)
            
            var decodedByteIndex = 0;
            for byteIndex in stride(from: 0, to: base32Data.count, by: 8) {
                let maxOffset = (byteIndex + 8 >= base32Data.count) ? base32Data.count : byteIndex + 8
                let numberOfBytes = maxOffset - byteIndex
                
                var encodedByte0: UInt8 = 0
                var encodedByte1: UInt8 = 0
                var encodedByte2: UInt8 = 0
                var encodedByte3: UInt8 = 0
                var encodedByte4: UInt8 = 0
                var encodedByte5: UInt8 = 0
                var encodedByte6: UInt8 = 0
                var encodedByte7: UInt8 = 0
                
                switch numberOfBytes {
                case 8:
                    encodedByte7 = UInt8(alphabet[Int( base32Bytes[byteIndex + 7] )])
                    fallthrough
                case 7:
                    encodedByte6 = UInt8(alphabet[Int( base32Bytes[byteIndex + 6] )])
                    fallthrough
                case 6:
                    encodedByte5 = UInt8(alphabet[Int( base32Bytes[byteIndex + 5] )])
                    fallthrough
                case 5:
                    encodedByte4 = UInt8(alphabet[Int( base32Bytes[byteIndex + 4] )])
                    fallthrough
                case 4:
                    encodedByte3 = UInt8(alphabet[Int( base32Bytes[byteIndex + 3] )])
                    fallthrough
                case 3:
                    encodedByte2 = UInt8(alphabet[Int( base32Bytes[byteIndex + 2] )])
                    fallthrough
                case 2:
                    encodedByte1 = UInt8(alphabet[Int( base32Bytes[byteIndex + 1] )])
                    fallthrough
                case 1:
                    encodedByte0 = UInt8(alphabet[Int( base32Bytes[byteIndex + 0] )])
                    fallthrough
                default:
                    break;
                }
                
                buffer[decodedByteIndex + 0] = ((encodedByte0 << 3) & 0xF8) | ((encodedByte1 >> 2) & 0x07)
                buffer[decodedByteIndex + 1] = ((encodedByte1 << 6) & 0xC0) | ((encodedByte2 << 1) & 0x3E) | ((encodedByte3 >> 4) & 0x01)
                buffer[decodedByteIndex + 2] = ((encodedByte3 << 4) & 0xF0) | ((encodedByte4 >> 1) & 0x0F)
                buffer[decodedByteIndex + 3] = ((encodedByte4 << 7) & 0x80) | ((encodedByte5 << 2) & 0x7C) | ((encodedByte6 >> 3) & 0x03)
                buffer[decodedByteIndex + 4] = ((encodedByte6 << 5) & 0xE0) | (encodedByte7 & 0x1F)
                
                decodedByteIndex += 5
            }
            
            return Data(bytesNoCopy: buffer, count: totalNumberOfBytes, deallocator: .free)
        }
        
        return nil
    }
    
    override func isEqual(_ object: Any?) -> Bool {
        if let otherDigitCode = object as? DigitCode {
            return secret == otherDigitCode.secret
        }
        return false
    }
    
    override var description: String {
        return "Secret: \(secret), totp: \(DigitCode.formatCode(totpToken ?? [Int]()) ?? "invalid")"
    }
    
    /** Formats a 6 digit code into the form, `000 000`, optionally with a different separator.
     - Parameters:
        - code: an `Int` array of length 6.
        - separator: optionally a separator to go between the two halves.
            The default separator is a single space.
    */
    static func formatCode(_ code: [Int], separator: String = " ") -> String? {
        if code.count != 6 { return nil }
        let left = code[0...2].map { String($0) }.joined()
        let right = code[3...5].map { String($0) }.joined()
        return left + separator + right
    }
}

extension String {
    /// A Boolean value that determines whether a secret is `RFC 4648` compliant
    var is16RFC4648Complaint: Bool {
        var charactersValid = true
        let validCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        characters.forEach {
            if !validCharacters.contains(String($0)) { charactersValid = false }
        }
        return characters.count == 16 && charactersValid
    }
}

/// The delegate for a DigitCode object.
protocol DigitCodeDelegate {
    /** Gets called with an array of 6 digits every 30 seconds, just after the true switch to a new totp token.
     - Parameter code: A 6 digit Int array representing the current totp token.
    */
    func totpTokenDidChange(code: [Int])
}
