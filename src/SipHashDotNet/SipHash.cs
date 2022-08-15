/*
    SipHash.NET: A .NET implementation of SipHash-2-4.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SipHashDotNet;

public static class SipHash
{
    public const int KeySize = 16;
    public const int TagSize = 8;
    private const int CRounds = 2;
    private const int DRounds = 4;
    
    public static unsafe void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (tag.Length != TagSize) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be {TagSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }
        
        // 1. Initialisation
        ulong k0 = BinaryPrimitives.ReadUInt64LittleEndian(key[..sizeof(ulong)]);
        ulong k1 = BinaryPrimitives.ReadUInt64LittleEndian(key[sizeof(ulong)..]);
        ulong v0 = k0 ^ 0x736f6d6570736575UL;
        ulong v1 = k1 ^ 0x646f72616e646f6dUL;
        ulong v2 = k0 ^ 0x6c7967656e657261UL;
        ulong v3 = k1 ^ 0x7465646279746573UL;
        ulong b;
        
        // 2. Compression
        fixed (byte* startPtr = message) {
            byte* endPtr = startPtr + message.Length - message.Length % sizeof(ulong);
            var bPtr = (ulong*) startPtr;
            while (bPtr < endPtr) {
                b = *bPtr++;
                
                v3 ^= b;

                for (int i = 0; i < CRounds; i++) {
                    v0 += v1;
                    v2 += v3;
                    v1 = v1 << 13 | v1 >> 51;
                    v3 = v3 << 16 | v3 >> 48;
                    v1 ^= v0;
                    v3 ^= v2;
                    v0 = v0 << 32 | v0 >> 32;
                    v2 += v1;
                    v0 += v3;
                    v1 = v1 << 17 | v1 >> 47;
                    v3 = v3 << 21 | v3 >> 43;
                    v1 ^= v2;
                    v3 ^= v0;
                    v2 = v2 << 32 | v2 >> 32;
                }

                v0 ^= b;
            }
            
            b = (ulong) message.Length << 56;
            switch (message.Length & 7) {
                case 7:
                    b |= *(uint*) endPtr | (ulong) *(ushort*) (endPtr + 4) << 32 | (ulong) *(endPtr + 6) << 48;
                    break;
                case 6:
                    b |= *(uint*) endPtr | (ulong) *(ushort*) (endPtr + 4) << 32;
                    break;
                case 5:
                    b |= *(uint*) endPtr | (ulong) *(endPtr + 4) << 32;
                    break;
                case 4:
                    b |= *(uint*) endPtr;
                    break;
                case 3:
                    b |= *(ushort*) endPtr | (ulong) *(endPtr + 2) << 16;
                    break;
                case 2:
                    b |= *(ushort*) endPtr;
                    break;
                case 1:
                    b |= *endPtr;
                    break;
                case 0:
                    break;
            }
        }
        
        v3 ^= b;
        
        for (int i = 0; i < CRounds; i++) {
            v0 += v1;
            v2 += v3;
            v1 = v1 << 13 | v1 >> 51;
            v3 = v3 << 16 | v3 >> 48;
            v1 ^= v0;
            v3 ^= v2;
            v0 = v0 << 32 | v0 >> 32;
            v2 += v1;
            v0 += v3;
            v1 = v1 << 17 | v1 >> 47;
            v3 = v3 << 21 | v3 >> 43;
            v1 ^= v2;
            v3 ^= v0;
            v2 = v2 << 32 | v2 >> 32;
        }
        
        v0 ^= b;
        
        // 3. Finalisation
        v2 ^= 0xff;
        
        for (int i = 0; i < DRounds; i++) {
            v0 += v1;
            v2 += v3;
            v1 = v1 << 13 | v1 >> 51;
            v3 = v3 << 16 | v3 >> 48;
            v1 ^= v0;
            v3 ^= v2;
            v0 = v0 << 32 | v0 >> 32;
            v2 += v1;
            v0 += v3;
            v1 = v1 << 17 | v1 >> 47;
            v3 = v3 << 21 | v3 >> 43;
            v1 ^= v2;
            v3 ^= v0;
            v2 = v2 << 32 | v2 >> 32;
        }
        
        BinaryPrimitives.WriteInt64LittleEndian(tag, (long) (v0 ^ v1 ^ v2 ^ v3));
    }

    public static bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        Span<byte> computedTag = stackalloc byte[TagSize];
        ComputeTag(computedTag, message, key);
        bool valid = CryptographicOperations.FixedTimeEquals(tag, computedTag);
        CryptographicOperations.ZeroMemory(computedTag);
        return valid;
    }
}