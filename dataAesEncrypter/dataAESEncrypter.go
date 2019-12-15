package dataAESEncrypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

type dataEncrypter struct {
	key           []byte // Une clé de la taille d'un bloc AES
	data          []byte
	encryptedData []byte
	decryptedData []byte
}

const (
	SizePerRoutine            = aes.BlockSize * 64
	MaxSimultaneousGoroutines = 4
)

/*
   Fonction effectuant le padding du tableau de bytes passé en paramètres pour l'aligner sur la
   taille d'un bloc AES
*/
func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

/*
   Fonction supprimant le padding du tableau de bytes passé en paramètres
   Renvoie une erreur si l'unpadding échoue (lorsque la clé de décodage est incorrecte)
*/
func unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}
	return src[:(length - unpadding)], nil
}

/*
Prend en paramètre une clé et un tableau de bytes et retourne un tableau de bytes chiffré par AES
avec la clé donnée.
*/
/*
func encrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	msg := pad(data)                                   // Alignement du tableau sur la taille d'un bloc AES
	ciphertext := make([]byte, aes.BlockSize+len(msg)) // Création du tableau qui contiendra les données chiffrées
	iv := ciphertext[:aes.BlockSize]                   // Génération du vecteur d'initialisation
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Chiffrement des données
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], msg)
	return ciphertext, nil
}
*/

func encrypt(key []byte, iv []byte, data []byte, output []byte, blockIndex int, lastBlock bool) {
	fmt.Printf("Encrypting block %d\n", blockIndex)
	block, _ := aes.NewCipher(key)

	var dataToEncrypt []byte

	if lastBlock {
		dataToEncrypt = data[blockIndex*SizePerRoutine:]
	} else {
		dataToEncrypt = data[blockIndex*SizePerRoutine : (blockIndex+1)*SizePerRoutine]
	}

	cipherText := make([]byte, len(dataToEncrypt))

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(cipherText, dataToEncrypt)

	for i, elt := range cipherText {
		output[i+aes.BlockSize+blockIndex*SizePerRoutine] = elt
	}
}

/*
Prend en paramètre une clé et un tableau de bytes et retourne un tableau de bytes déchiffré par AES
avec la clé donnée.
*/
/*
func decrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Si la taille n'est pas un multiple de la taille de bloc AES, on ne peut pas déchiffrer
	if (len(data) % aes.BlockSize) != 0 {
		return nil, errors.New("blocksize must be multipe of decoded message length")
	}

	// On récupère l'IV et le message
	iv := data[:aes.BlockSize]
	msg := data[aes.BlockSize:]

	// On déchiffre
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	// On supprime l'alignement du message
	unpadMsg, err := unpad(msg)
	if err != nil {
		return nil, err
	}

	return unpadMsg, nil
}
*/

/*
func decryptGoEnd(key []byte, iv []byte, data []byte, output []byte, blockIndex int) {
	block, _ := aes.NewCipher(key)

	dataToDecrypt := data[:blockIndex*SizePerRoutine]
	decryptedData := make([]byte, len(dataToDecrypt))

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(decryptedData, dataToDecrypt)

	for i, elt := range decryptedData {
		output[i + aes.BlockSize + blockIndex*SizePerRoutine] = elt
	}
}
*/

func decrypt(key []byte, iv []byte, data []byte, output []byte, blockIndex int, lastBlock bool) {
	fmt.Printf("Decrypting block %d\n", blockIndex)
	block, _ := aes.NewCipher(key)

	var dataToDecrypt []byte

	if lastBlock {
		dataToDecrypt = data[blockIndex*SizePerRoutine:]
	} else {
		dataToDecrypt = data[blockIndex*SizePerRoutine : (blockIndex+1)*SizePerRoutine]
	}

	decryptedData := make([]byte, len(dataToDecrypt))

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(decryptedData, dataToDecrypt)

	for i, elt := range decryptedData {
		output[blockIndex*SizePerRoutine+i] = elt
	}
}

func (encrypter *dataEncrypter) SetKey(key []byte) {
	encrypter.key = key
}

func (encrypter *dataEncrypter) SetStringKey(key string) {
	h := sha256.New()
	h.Write([]byte(key))

	encrypter.key = h.Sum(nil)[:aes.BlockSize]
}

func (encrypter *dataEncrypter) SetData(data []byte) {
	encrypter.data = data
}

/*
func (this *dataEncrypter) Encrypt() error {
	this.decryptedData = this.data
	this.data = nil

	var err error
	this.encryptedData, err = encrypt(this.key, this.decryptedData)

	return err
}
*/

func (encrypter *dataEncrypter) Encrypt() error {
	encrypter.decryptedData = encrypter.data
	encrypter.data = nil

	data := pad(encrypter.decryptedData)
	result := make([]byte, aes.BlockSize+len(data))

	iv := result[:aes.BlockSize] // Génération du vecteur d'initialisation
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	totalRoutinesNeeded := int(math.Ceil(float64(len(data))/SizePerRoutine)) - 1

	indexChan := make(chan int, totalRoutinesNeeded)
	var wg sync.WaitGroup

	// On chiffre le dernier bloc d'abord
	go encrypt(encrypter.key, iv, data, result, totalRoutinesNeeded, true)

	wg.Add(MaxSimultaneousGoroutines)

	for i := 0; i < MaxSimultaneousGoroutines; i++ {
		go func() {
			for {
				blocIndex, elementsLeft := <-indexChan

				if !elementsLeft {
					wg.Done()
					return
				}

				encrypt(encrypter.key, iv, data, result, blocIndex, false)
			}
		}()
	}

	for i := 0; i < totalRoutinesNeeded; i++ {
		indexChan <- i
	}

	close(indexChan)
	wg.Wait()

	encrypter.encryptedData = result
	fmt.Println("Done encrypting")

	return nil
}

/*
func (this *dataEncrypter) Decrypt() error {
	this.encryptedData = this.data
	this.data = nil

	var err error
	this.decryptedData, err = decrypt(this.key, this.encryptedData)

	return err
}
*/

func (encrypter *dataEncrypter) Decrypt() error {
	encrypter.encryptedData = encrypter.data
	encrypter.data = nil

	var err error

	if len(encrypter.encryptedData)%aes.BlockSize != 0 {
		return errors.New("blocksize must be multipe of decoded message length")
	}

	iv := encrypter.encryptedData[:aes.BlockSize]
	data := encrypter.encryptedData[aes.BlockSize:]

	result := make([]byte, len(data))

	totalRoutinesNeeded := int(math.Ceil(float64(len(data))/SizePerRoutine)) - 1

	indexChan := make(chan int, totalRoutinesNeeded)
	var wg sync.WaitGroup

	go decrypt(encrypter.key, iv, data, result, totalRoutinesNeeded, true)

	wg.Add(MaxSimultaneousGoroutines)

	for i := 0; i < MaxSimultaneousGoroutines; i++ {
		go func() {
			for {
				blocIndex, elementsLeft := <-indexChan

				if !elementsLeft {
					wg.Done()
					return
				}

				decrypt(encrypter.key, iv, data, result, blocIndex, false)
			}
		}()
	}

	for i := 0; i < totalRoutinesNeeded; i++ {
		indexChan <- i
	}

	close(indexChan)
	wg.Wait()

	encrypter.decryptedData, err = unpad(result)
	fmt.Println("Done decrypting")

	return err
}

func (encrypter dataEncrypter) GetEncryptedData() []byte {
	return encrypter.encryptedData
}

func (encrypter dataEncrypter) GetDecryptedData() []byte {
	return encrypter.decryptedData
}

func New() *dataEncrypter {
	return &dataEncrypter{}
}

func (encrypter dataEncrypter) String() string {
	return fmt.Sprintf("Key: %x\nData: %x\nData (string): %s\nEncrypted data: %x\nDecrypted data: %x\n",
		encrypter.key, encrypter.data, encrypter.data, encrypter.encryptedData, encrypter.decryptedData)
}
