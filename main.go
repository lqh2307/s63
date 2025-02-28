package s63

import (
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"log"

	"golang.org/x/crypto/blowfish"
)

// // BlowFish struct chứa cipher block và IV
// type BlowFish struct {
// 	cipher cipher.Block
// 	iv     []byte
// }

// // NewBlowFish khởi tạo Blowfish với khóa
// func NewBlowFish(key []byte) *BlowFish {
// 	block, err := blowfish.NewCipher(key)
// 	if err != nil {
// 		log.Fatalf("Lỗi tạo Blowfish: %v", err)
// 	}
// 	return &BlowFish{
// 		cipher: block,
// 		iv:     make([]byte, blowfish.BlockSize), // Mặc định IV là 8 byte
// 	}
// }

// // EncryptECB mã hóa theo chế độ ECB
// func (bf *BlowFish) EncryptECB(data []byte) []byte {
// 	blockSize := bf.cipher.BlockSize()
// 	ciphertext := make([]byte, len(data))

// 	for i := 0; i < len(data); i += blockSize {
// 		bf.cipher.Encrypt(ciphertext[i:], data[i:])
// 	}
// 	return ciphertext
// }

// // DecryptECB giải mã theo chế độ ECB
// func (bf *BlowFish) DecryptECB(data []byte) []byte {
// 	blockSize := bf.cipher.BlockSize()
// 	plaintext := make([]byte, len(data))

// 	for i := 0; i < len(data); i += blockSize {
// 		bf.cipher.Decrypt(plaintext[i:], data[i:])
// 	}
// 	return plaintext
// }

// // EncryptCBC mã hóa theo chế độ CBC
// func (bf *BlowFish) EncryptCBC(plainText []byte) []byte {
// 	mode := cipher.NewCBCEncrypter(bf.cipher, bf.iv)
// 	ciphertext := make([]byte, len(plainText))
// 	mode.CryptBlocks(ciphertext, plainText)
// 	return ciphertext
// }

// // DecryptCBC giải mã theo chế độ CBC
// func (bf *BlowFish) DecryptCBC(cipherText []byte) []byte {
// 	mode := cipher.NewCBCDecrypter(bf.cipher, bf.iv)
// 	plaintext := make([]byte, len(cipherText))
// 	mode.CryptBlocks(plaintext, cipherText)
// 	return plaintext
// }

// // SetIV đặt giá trị IV mới
// func (bf *BlowFish) SetIV(iv []byte) error {
// 	if len(iv) != blowfish.BlockSize {
// 		return fmt.Errorf("IV phải dài %d byte", blowfish.BlockSize)
// 	}
// 	bf.iv = iv
// 	return nil
// }

// func main() {
// 	key := []byte("mysecretkey123")
// 	plaintext := []byte("Hello123") // Phải là bội số của 8 byte

// 	bf := blowfish.NewBlowFish(key)

// 	// Mã hóa ECB
// 	encrypted := bf.EncryptECB(plaintext)
// 	fmt.Printf("Mã hóa ECB: %x\n", encrypted)

// 	// Giải mã ECB
// 	decrypted := bf.DecryptECB(encrypted)
// 	fmt.Printf("Giải mã ECB: %s\n", decrypted)

// 	// Mã hóa CBC
// 	encryptedCBC := bf.EncryptCBC(plaintext)
// 	fmt.Printf("Mã hóa CBC: %x\n", encryptedCBC)

// 	// Giải mã CBC
// 	decryptedCBC := bf.DecryptCBC(encryptedCBC)
// 	fmt.Printf("Giải mã CBC: %s\n", decryptedCBC)
// }

// BlowFish struct
type BlowFish struct {
	cipher cipher.Block
}

// NewBlowFish khởi tạo Blowfish với khóa
func NewBlowFish(key []byte) (*BlowFish, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &BlowFish{cipher: block}, nil
}

// EncryptECB mã hóa dữ liệu theo ECB mode
func (bf *BlowFish) EncryptECB(data []byte) []byte {
	blockSize := bf.cipher.BlockSize()
	ciphertext := make([]byte, len(data))

	for i := 0; i < len(data); i += blockSize {
		bf.cipher.Encrypt(ciphertext[i:], data[i:])
	}

	return ciphertext
}

// DecryptECB giải mã dữ liệu theo ECB mode
func (bf *BlowFish) DecryptECB(data []byte) []byte {
	blockSize := bf.cipher.BlockSize()
	plaintext := make([]byte, len(data))

	for i := 0; i < len(data); i += blockSize {
		bf.cipher.Decrypt(plaintext[i:], data[i:])
	}

	return plaintext
}

// ComputeCRC32 tính CRC32 của dữ liệu
func ComputeCRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

// CreateUserPermit tạo User Permit từ HW ID
func CreateUserPermit(hwId, key []byte, mId uint16) (string, error) {
	if len(hwId) != 5 {
		return "", errors.New("invalid HW ID length")
	}

	// Chuẩn bị block 8 byte
	hwIdBlock := make([]byte, 8)
	copy(hwIdBlock, hwId)
	hwIdBlock[5], hwIdBlock[6], hwIdBlock[7] = 3, 3, 3

	// Mã hóa bằng Blowfish
	blow, err := NewBlowFish(key)
	if err != nil {
		return "", err
	}
	enc := blow.EncryptECB(hwIdBlock)

	// Chuyển sang chuỗi HEX
	permit := make([]byte, 28)
	hex.Encode(permit[:16], enc)

	// Tính CRC32
	crc := ComputeCRC32(permit[:16])
	binary.BigEndian.PutUint32(permit[16:], crc)
	binary.BigEndian.PutUint16(permit[24:], mId)

	return string(permit), nil
}

// DecryptUserPermit giải mã User Permit
func DecryptUserPermit(userPermit string, key []byte) ([]byte, uint16, error) {
	permit := []byte(userPermit)

	// Kiểm tra CRC32
	crc := ComputeCRC32(permit[:16])
	crc2 := binary.BigEndian.Uint32(permit[16:20])
	if crc != crc2 {
		return nil, 0, errors.New("invalid CRC")
	}

	mId := binary.BigEndian.Uint16(permit[24:28])

	// Giải mã bằng Blowfish
	blow, err := NewBlowFish(key)
	if err != nil {
		return nil, 0, err
	}

	hwIdBlock := make([]byte, 8)
	_, err = hex.Decode(hwIdBlock, permit[:16])
	if err != nil {
		return nil, 0, err
	}

	hwIdBlock = blow.DecryptECB(hwIdBlock)

	// Kiểm tra hợp lệ
	if hwIdBlock[5] != 3 || hwIdBlock[6] != 3 || hwIdBlock[7] != 3 {
		return nil, 0, errors.New("invalid HW ID")
	}

	return hwIdBlock[:5], mId, nil
}

// CreateCellPermit tạo Cell Permit
func CreateCellPermit(hwId []byte, cellName string, expiryDate string, ck1, ck2 []byte) (string, error) {
	if len(hwId) != 5 || len(ck1) != 5 || len(ck2) != 5 {
		return "", errors.New("invalid length")
	}

	// Tạo HW ID 6 byte
	hwId6 := append(hwId, hwId[0])

	permit := make([]byte, 64)
	copy(permit, []byte(cellName))
	copy(permit[8:], expiryDate)

	blow, err := NewBlowFish(hwId6)
	if err != nil {
		return "", err
	}

	// Mã hóa ck1 và ck2
	block := make([]byte, 8)
	copy(block, ck1)
	block[5], block[6], block[7] = 3, 3, 3
	enc1 := blow.EncryptECB(block)

	copy(block, ck2)
	enc2 := blow.EncryptECB(block)

	// Chuyển sang HEX
	hex.Encode(permit[16:], enc1)
	hex.Encode(permit[32:], enc2)

	// Tính CRC32
	crc := ComputeCRC32(permit[:48])
	binary.BigEndian.PutUint32(block, crc)
	block[4], block[5], block[6], block[7] = 4, 4, 4, 4
	encCRC := blow.EncryptECB(block)
	hex.Encode(permit[48:], encCRC)

	return string(permit), nil
}

// TryDecryptCellPermit giải mã Cell Permit
func TryDecryptCellPermit(cellPermit string, hwId []byte) ([]byte, []byte, error) {
	permit := []byte(cellPermit)
	crc := ComputeCRC32(permit[:48])

	hwId6 := append(hwId, hwId[0])
	blow, err := NewBlowFish(hwId6)
	if err != nil {
		return nil, nil, err
	}

	// Giải mã CRC
	block := make([]byte, 8)
	_, err = hex.Decode(block, permit[48:])
	if err != nil {
		return nil, nil, err
	}

	crcBlock := blow.DecryptECB(block)
	if crcBlock[4] != 4 || binary.BigEndian.Uint32(crcBlock[:4]) != crc {
		return nil, nil, errors.New("invalid CRC")
	}

	// Giải mã ck1
	_, err = hex.Decode(block, permit[16:])
	if err != nil {
		return nil, nil, err
	}
	ck1Block := blow.DecryptECB(block)
	if ck1Block[5] != 3 {
		return nil, nil, errors.New("invalid Cell Key 1")
	}

	// Giải mã ck2
	_, err = hex.Decode(block, permit[32:])
	if err != nil {
		return nil, nil, err
	}
	ck2Block := blow.DecryptECB(block)
	if ck2Block[5] != 3 {
		return nil, nil, errors.New("invalid Cell Key 2")
	}

	return ck1Block[:5], ck2Block[:5], nil
}
