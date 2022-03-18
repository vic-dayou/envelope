package sm3

import (
	"encoding/binary"
	"hash"
)

type SM3 struct {
	digest [8]uint32
	length uint64
	m      []byte
}

// The size of a SM3 checksum in bytes.
const Size = 32

// The blocksize of SM3 in bytes.
const BlockSize = 64

// 算法常量，随j的变化取不同值； T0: 0=<j<=15;T1:16=<j<=63
const T0 = 0x79cc4519
const T1 = 0x7a879d8a

func New() hash.Hash {
	var sm3 SM3
	sm3.Reset()
	return &sm3
}

func (sm3 *SM3) Size() int {
	return Size
}

func (sm3 *SM3) BlockSize() int {
	return BlockSize
}

// 布尔函数
func (sm3 *SM3) ff0(x, y, z uint32) uint32 { return x ^ y ^ z }
func (sm3 *SM3) ff1(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
func (sm3 *SM3) gg0(x, y, z uint32) uint32 { return x ^ y ^ z }
func (sm3 *SM3) gg1(x, y, z uint32) uint32 { return (x & y) | (^x & z) }

// 置换函数
func (sm3 *SM3) p0(x uint32) uint32 { return x ^ sm3.leftRotate(x, 9) ^ sm3.leftRotate(x, 17) }
func (sm3 *SM3) p1(x uint32) uint32 { return x ^ sm3.leftRotate(x, 15) ^ sm3.leftRotate(x, 23) }

func (sm3 *SM3) leftRotate(x, i uint32) uint32 { return x<<(i%32) | x>>(32-i%32) }

// 填充: 假设消息m的长度为l比特,则首先将比特 ‘1’ 添加到消息的末尾，再添加 k 个 ‘0’，k 满足 l+1+k = 448
// 再添加一个64位比特串，该比特串是长度 l 的二进制表示。填充后的消息 m‘ 的比特长度为512的倍数
// 例如：m=01100001 01100010 01100011，l=24，则 k = 423
func (sm3 *SM3) padding() []byte {
	msg := sm3.m
	msg = append(msg, 0x80) // 添加 1 个 ‘1’ 比特的同时添加了 7 个‘0’ 比特，则k需要满足 l + 1 + 7 + k = 448
	for len(msg)%BlockSize != 56 {
		msg = append(msg, 0x00)
	}
	// append message length
	msg = append(msg, uint8(sm3.length>>56&0xff))
	msg = append(msg, uint8(sm3.length>>48&0xff))
	msg = append(msg, uint8(sm3.length>>40&0xff))
	msg = append(msg, uint8(sm3.length>>32&0xff))
	msg = append(msg, uint8(sm3.length>>24&0xff))
	msg = append(msg, uint8(sm3.length>>16&0xff))
	msg = append(msg, uint8(sm3.length>>8&0xff))
	msg = append(msg, uint8(sm3.length>>0&0xff))
	return msg
}

func (sm3 *SM3) Reset() {
	// Reset digest
	sm3.digest[0] = 0x7380166f
	sm3.digest[1] = 0x4914b2b9
	sm3.digest[2] = 0x172442d7
	sm3.digest[3] = 0xda8a0600
	sm3.digest[4] = 0xa96f30bc
	sm3.digest[5] = 0x163138aa
	sm3.digest[6] = 0xe38dee4d
	sm3.digest[7] = 0xb0fb0e4e

	sm3.length = 0 // Reset numberic states
	sm3.m = []byte{}
}

func (sm3 *SM3) Write(m []byte) (int, error) {
	length := len(m)
	sm3.length += uint64(len(m) * 8)
	msg := append(sm3.m, m...)
	nblock := len(msg) / BlockSize
	sm3.update(msg)
	sm3.m = msg[nblock*BlockSize:]
	return length, nil
}

func (sm3 *SM3) Sum(in []byte) []byte {
	_, _ = sm3.Write(in)
	msg := sm3.padding()
	sm3.update(msg)
	out := make([]byte, Size)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], sm3.digest[i])
	}
	return append(in, out...)
}

func (sm3 *SM3) update(m []byte) {
	var w [68]uint32
	var w1 [64]uint32
	a, b, c, d, e, f, g, h := sm3.digest[0], sm3.digest[1], sm3.digest[2], sm3.digest[3], sm3.digest[4], sm3.digest[5], sm3.digest[6], sm3.digest[7]

	for len(m) >= 64 {
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(m[4*i : 4*(i+1)])
		}

		for i := 16; i <= 67; i++ {
			w[i] = sm3.p1(w[i-16]^w[i-9]^sm3.leftRotate(w[i-3], 15)) ^ sm3.leftRotate(w[i-13], 7) ^ w[i-6]
		}

		for i := 0; i <= 63; i++ {
			w1[i] = w[i] ^ w[i+4]
		}

		A, B, C, D, E, F, G, H := a, b, c, d, e, f, g, h
		for i := 0; i < 16; i++ {
			SS1 := sm3.leftRotate(sm3.leftRotate(A, 12)+E+sm3.leftRotate(0x79cc4519, uint32(i)), 7)
			SS2 := SS1 ^ sm3.leftRotate(A, 12)
			TT1 := sm3.ff0(A, B, C) + D + SS2 + w1[i]
			TT2 := sm3.gg0(E, F, G) + H + SS1 + w[i]
			D = C
			C = sm3.leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = sm3.leftRotate(F, 19)
			F = E
			E = sm3.p0(TT2)
		}
		for i := 16; i < 64; i++ {
			SS1 := sm3.leftRotate(sm3.leftRotate(A, 12)+E+sm3.leftRotate(0x7a879d8a, uint32(i)), 7)
			SS2 := SS1 ^ sm3.leftRotate(A, 12)
			TT1 := sm3.ff1(A, B, C) + D + SS2 + w1[i]
			TT2 := sm3.gg1(E, F, G) + H + SS1 + w[i]
			D = C
			C = sm3.leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = sm3.leftRotate(F, 19)
			F = E
			E = sm3.p0(TT2)
		}
		a ^= A
		b ^= B
		c ^= C
		d ^= D
		e ^= E
		f ^= F
		g ^= G
		h ^= H
		m = m[64:]
	}
	sm3.digest[0], sm3.digest[1], sm3.digest[2], sm3.digest[3], sm3.digest[4], sm3.digest[5], sm3.digest[6], sm3.digest[7] = a, b, c, d, e, f, g, h
}

func Sm3Sum(data []byte) []byte {
	var sm3 SM3

	sm3.Reset()
	_, _ = sm3.Write(data)
	return sm3.Sum(nil)
}
