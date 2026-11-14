package emailparser

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// Builds a synthetic CFB container: no real email or personal data is committed.
func syntheticMSG() []byte {
	b := make([]byte, 19*512)
	copy(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	u16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	u32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	u16(24, 0x3e)
	u16(26, 3)
	u16(28, 0xfffe)
	u16(30, 9)
	u16(32, 6)
	u32(44, 1)
	u32(48, 1)
	u32(56, 4096)
	u32(60, 0xfffffffe)
	u32(68, 0xfffffffe)
	for i := 76; i < 512; i += 4 {
		u32(i, 0xffffffff)
	}
	u32(76, 0)
	for i := 512; i < 1024; i += 4 {
		u32(i, 0xffffffff)
	}
	u32(512, 0xfffffffd)
	u32(516, 0xfffffffe)
	for i := 2; i < 18; i++ {
		next := uint32(i + 1)
		if i == 9 || i == 17 {
			next = 0xfffffffe
		}
		u32(512+i*4, next)
	}
	entry := func(index int, name string, typ byte, start, size, right, child uint32) {
		off := 1024 + index*128
		units := utf16.Encode([]rune(name + "\x00"))
		for i, v := range units {
			u16(off+2*i, v)
		}
		u16(off+64, uint16(len(units)*2))
		b[off+66] = typ
		b[off+67] = 1
		u32(off+68, 0xffffffff)
		u32(off+72, right)
		u32(off+76, child)
		u32(off+116, start)
		u32(off+120, size)
	}
	entry(0, "Root Entry", 5, 0xfffffffe, 0, 0xffffffff, 1)
	entry(1, "__properties_version1.0", 2, 2, 4096, 2, 0xffffffff)
	entry(2, "__substg1.0_1000001F", 2, 10, 4096, 0xffffffff, 0xffffffff)
	u32(1536+32, 0x1000001f)
	u32(1536+40, 4096)
	for i, v := range utf16.Encode([]rune("Synthetic message body\x00")) {
		u16(5632+i*2, v)
	}
	return b
}
func TestSyntheticMSG(t *testing.T) {
	e, err := ParseMSG(syntheticMSG(), "test.msg")
	if err != nil {
		t.Fatal(err)
	}
	if e.Source != "msg" || e.SHA256 == "" || !strings.HasPrefix(e.Text, "Synthetic message body") {
		t.Fatal("normalization")
	}
	if _, err = ParseMSG([]byte("corrupt"), "bad.msg"); err == nil {
		t.Fatal("invalid format accepted")
	}
}
