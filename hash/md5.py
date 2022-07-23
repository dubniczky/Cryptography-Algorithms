#!/usr/bin/env python3

'''
Implementation of the md5 hash algorithm in python.
This library is for learning purposes, so built-in functions should be preferred.
https://github.com/dubniczky/Cryptography-Algorithms
'''


import binascii
from typing import Callable


start_chunks = {
    'A': 0x67452301,
    'B': 0xefcdab89,
    'C': 0x98badcfe,
    'D': 0x10325476
}

SV = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
    0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
    0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
    0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
    0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
    0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
    0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
    0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]


def bit_rotate_left(target: int, shift: int) -> int:
    shift = shift % 32 # Only rotate by 31 bits max
    target = target % (2 ** 32) # Only allow 32 bit integers
    upper = (target << shift) % (2 ** 32)
    return upper | (target >> (32 - shift))


def block_to_chunks(block: bytes, chunk_size: int) -> list[int]:
    chunk_count = len(block) // chunk_size
    chunks = []
    for i in range(chunk_size):
        low = i * chunk_count
        high = low + chunk_count
        chunks.append( int.from_bytes( block[low:high], byteorder="little" ))
    return chunks


def F(X: int, Y: int, Z: int) -> int:
    return (X & Y) | ((~X) & Z)


def G(X: int, Y: int, Z: int) -> int:
    return (X & Z) | (Y & (~Z))


def H(X: int, Y: int, Z: int) -> int:
    return X ^ Y ^ Z


def I(X: int, Y: int, Z: int) -> int:
    return Y ^ (X | (~Z))


def rot_func(func: Callable[[int,int,int], int],
             a: int, b: int, c: int, d: int, M: int, s: int, t: int):
    return b + bit_rotate_left( (a + func(b,c,d) + M + t) , s)


def format_int32(num: int) -> str:
    return (num).to_bytes(4, byteorder='little').hex().lower()


def bit_count(b: bytes) -> int:
    return len(b) * 8


def md5(data: str|bytes) -> str:
    # Convert format
    if isinstance(data, str):
        data = bytes(data, encoding='utf-8')

    # Apply padding
    length = bit_count(data) % (2**64)
    data = data + b'\x80' # Bits: 1000 0000
    pad_zero_length = ( (448 - (length+8) % 512) % 512 ) // 8
    data = data + b'\x00' * pad_zero_length + length.to_bytes(8, byteorder='little')
    length = bit_count(data)
    iterations = length // 512

    # Init start values
    A = start_chunks['A']
    B = start_chunks['B']
    C = start_chunks['C']
    D = start_chunks['D']

    # Calculate rounds
    for i in range(iterations):
        a = A
        b = B
        c = C
        d = D
        block = data[i*64:(i+1)*64]
        M = block_to_chunks(block, 16)

        a = rot_func(F, a,b,c,d, M[0], 7, SV[0] )
        d = rot_func(F, d,a,b,c, M[1], 12, SV[1] )
        c = rot_func(F, c,d,a,b, M[2], 17, SV[2] )
        b = rot_func(F, b,c,d,a, M[3], 22, SV[3] )

        a = rot_func(F, a,b,c,d, M[4], 7, SV[4] )
        d = rot_func(F, d,a,b,c, M[5], 12, SV[5] )
        c = rot_func(F, c,d,a,b, M[6], 17, SV[6] )
        b = rot_func(F, b,c,d,a, M[7], 22, SV[7] )

        a = rot_func(F, a,b,c,d, M[8], 7, SV[8] )
        d = rot_func(F, d,a,b,c, M[9], 12, SV[9] )
        c = rot_func(F, c,d,a,b, M[10], 17, SV[10] )
        b = rot_func(F, b,c,d,a, M[11], 22, SV[11] )

        a = rot_func(F, a,b,c,d, M[12], 7, SV[12] )
        d = rot_func(F, d,a,b,c, M[13], 12, SV[13] )
        c = rot_func(F, c,d,a,b, M[14], 17, SV[14] )
        b = rot_func(F, b,c,d,a, M[15], 22, SV[15] )

        a = rot_func(G, a,b,c,d, M[1], 5, SV[16] )
        d = rot_func(G, d,a,b,c, M[6], 9, SV[17] )
        c = rot_func(G, c,d,a,b, M[11], 14, SV[18] )
        b = rot_func(G, b,c,d,a, M[0], 20, SV[19] )

        a = rot_func(G, a,b,c,d, M[5], 5, SV[20] )
        d = rot_func(G, d,a,b,c, M[10], 9, SV[21] )
        c = rot_func(G, c,d,a,b, M[15], 14, SV[22] )
        b = rot_func(G, b,c,d,a, M[4], 20, SV[23] )

        a = rot_func(G, a,b,c,d, M[9], 5, SV[24] )
        d = rot_func(G, d,a,b,c, M[14], 9, SV[25] )
        c = rot_func(G, c,d,a,b, M[3], 14, SV[26] )
        b = rot_func(G, b,c,d,a, M[8], 20, SV[27] )

        a = rot_func(G, a,b,c,d, M[13], 5, SV[28] )
        d = rot_func(G, d,a,b,c, M[2], 9, SV[29] )
        c = rot_func(G, c,d,a,b, M[7], 14, SV[30] )
        b = rot_func(G, b,c,d,a, M[12], 20, SV[31] )

        a = rot_func(H, a,b,c,d, M[5], 4, SV[32] )
        d = rot_func(H, d,a,b,c, M[8], 11, SV[33] )
        c = rot_func(H, c,d,a,b, M[11], 16, SV[34] )
        b = rot_func(H, b,c,d,a, M[14], 23, SV[35] )

        a = rot_func(H, a,b,c,d, M[1], 4, SV[36] )
        d = rot_func(H, d,a,b,c, M[4], 11, SV[37] )
        c = rot_func(H, c,d,a,b, M[7], 16, SV[38] )
        b = rot_func(H, b,c,d,a, M[10], 23, SV[39] )

        a = rot_func(H, a,b,c,d, M[13], 4, SV[40] )
        d = rot_func(H, d,a,b,c, M[0], 11, SV[41] )
        c = rot_func(H, c,d,a,b, M[3], 16, SV[42] )
        b = rot_func(H, b,c,d,a, M[6], 23, SV[43] )

        a = rot_func(H, a,b,c,d, M[9], 4, SV[44] )
        d = rot_func(H, d,a,b,c, M[12], 11, SV[45] )
        c = rot_func(H, c,d,a,b, M[15], 16, SV[46] )
        b = rot_func(H, b,c,d,a, M[2], 23, SV[47] )

        a = rot_func(I, a,b,c,d, M[0], 6, SV[48] )
        d = rot_func(I, d,a,b,c, M[7], 10, SV[49] )
        c = rot_func(I, c,d,a,b, M[14], 15, SV[50] )
        b = rot_func(I, b,c,d,a, M[5], 21, SV[51] )

        a = rot_func(I, a,b,c,d, M[12], 6, SV[52] )
        d = rot_func(I, d,a,b,c, M[3], 10, SV[53] )
        c = rot_func(I, c,d,a,b, M[10], 15, SV[54] )
        b = rot_func(I, b,c,d,a, M[1], 21, SV[55] )

        a = rot_func(I, a,b,c,d, M[8], 6, SV[56] )
        d = rot_func(I, d,a,b,c, M[15], 10, SV[57] )
        c = rot_func(I, c,d,a,b, M[6], 15, SV[58] )
        b = rot_func(I, b,c,d,a, M[13], 21, SV[59] )

        a = rot_func(I, a,b,c,d, M[4], 6, SV[60] )
        d = rot_func(I, d,a,b,c, M[11], 10, SV[61] )
        c = rot_func(I, c,d,a,b, M[2], 15, SV[62] )
        b = rot_func(I, b,c,d,a, M[9], 21, SV[63] )

        A = (A + a) % (2**32)
        B = (B + b) % (2**32)
        C = (C + c) % (2**32)
        D = (D + d) % (2**32)

    return format_int32(A) + format_int32(B) + format_int32(C) + format_int32(D)


# Direct run as CLI app
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print('Missing parameter: [data]')
        sys.exit(1)
    print(md5(sys.argv[1]))
