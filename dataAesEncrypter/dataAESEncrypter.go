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
)

type dataEncrypter struct {
    key []byte // Une clé de la taille d'un bloc AES
    data []byte
    encryptedData []byte
    decryptedData []byte
}

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
func encrypt(key []byte, data []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    msg := pad(data) // Alignement du tableau sur la taille d'un bloc AES
    ciphertext := make([]byte, aes.BlockSize+len(msg)) // Création du tableau qui contiendra les données chiffrées
    iv := ciphertext[:aes.BlockSize] // Génération du vecteur d'initialisation
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    // Chiffrement des données
    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], msg)
    return ciphertext, nil
}

/*
Prend en paramètre une clé et un tableau de bytes et retourne un tableau de bytes déchiffré par AES
avec la clé donnée.
*/
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

func (this *dataEncrypter) SetKey(key []byte) {
    this.key = key
}

func (this *dataEncrypter) SetStringKey(key string) {
    h := sha256.New()
    h.Write([]byte(key))

    this.key = h.Sum(nil)[:aes.BlockSize]
}

func (this *dataEncrypter) SetData(data []byte) {
    this.data = data
}

func (this *dataEncrypter) Encrypt() error {
    this.decryptedData = this.data
    this.data = nil

    var err error
    this.encryptedData, err = encrypt(this.key, this.decryptedData)

    return err
}

func (this *dataEncrypter) Decrypt() error {
    this.encryptedData = this.data
    this.data = nil

    var err error
    this.decryptedData, err = decrypt(this.key, this.encryptedData)

    return err
}

func (this dataEncrypter) GetEncryptedData() []byte {
    return this.encryptedData
}

func (this dataEncrypter) GetDecryptedData () []byte {
    return this.decryptedData
}

func New() *dataEncrypter{
    return &dataEncrypter{}
}

func (this dataEncrypter) String() string {
    return fmt.Sprintf("Key: %x\nData: %x\nData (string): %s\nEncrypted data: %x\nDecrypted data: %x\n",
        this.key, this.data, this.data, this.encryptedData, this.decryptedData)
}