package detect

import "math/bits"

// keccakRate is the sponge rate of Keccak-256 in bytes: 200 - 2*32.
const keccakRate = 136

// keccakRC are the round constants of Keccak-f[1600].
var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// keccakRot are the rho rotation offsets, in the order the pi step visits the
// lanes.
var keccakRot = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}

// keccakPi is the lane each rho/pi step moves into, in visiting order.
var keccakPi = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

// keccak256 returns the Keccak-256 digest of data: the original Keccak with
// padding 0x01 ... 0x80, as Ethereum uses it. This is not SHA-3, which pads
// with 0x06 and so gives different digests.
func keccak256(data []byte) [32]byte {
	var st [25]uint64
	for len(data) >= keccakRate {
		keccakAbsorb(&st, data[:keccakRate])
		data = data[keccakRate:]
	}
	var last [keccakRate]byte
	copy(last[:], data)
	last[len(data)] ^= 0x01
	last[keccakRate-1] ^= 0x80
	keccakAbsorb(&st, last[:])

	var out [32]byte
	for i := range out {
		out[i] = byte(st[i/8] >> (8 * (i % 8)))
	}
	return out
}

// keccakAbsorb XORs one rate-sized block into the state, little-endian, and
// permutes it.
func keccakAbsorb(st *[25]uint64, block []byte) {
	for i := 0; i < keccakRate/8; i++ {
		var lane uint64
		for j := 7; j >= 0; j-- {
			lane = lane<<8 | uint64(block[8*i+j])
		}
		st[i] ^= lane
	}
	keccakF(st)
}

// keccakF is the Keccak-f[1600] permutation.
func keccakF(a *[25]uint64) {
	for _, rc := range keccakRC {
		// theta
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
			for y := 0; y < 25; y += 5 {
				a[y+x] ^= d
			}
		}
		// rho and pi
		t := a[1]
		for i := 0; i < 24; i++ {
			j := keccakPi[i]
			next := a[j]
			a[j] = bits.RotateLeft64(t, keccakRot[i])
			t = next
		}
		// chi
		for y := 0; y < 25; y += 5 {
			var row [5]uint64
			copy(row[:], a[y:y+5])
			for x := 0; x < 5; x++ {
				a[y+x] = row[x] ^ (^row[(x+1)%5] & row[(x+2)%5])
			}
		}
		// iota
		a[0] ^= rc
	}
}
