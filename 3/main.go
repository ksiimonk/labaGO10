package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Генерация пары ключей RSA и сохранение их в файлы
func generateKeys() error {
	// Генерируем приватный ключ
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Кодируем приватный ключ в PEM формат
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Сохраняем приватный ключ в файл
	err = ioutil.WriteFile("private_key.pem", pem.EncodeToMemory(privatePEM), 0600)
	if err != nil {
		return err
	}

	// Извлекаем публичный ключ из приватного
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	// Кодируем публичный ключ в PEM формат
	publicPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Сохраняем публичный ключ в файл
	err = ioutil.WriteFile("public_key.pem", pem.EncodeToMemory(publicPEM), 0644)
	if err != nil {
		return err
	}

	return nil
}

// Загрузка приватного ключа из файла
func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Загрузка публичного ключа из файла
func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	publicKeyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyData)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Публичный ключ в формате rsa.PublicKey
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("not an RSA public key")
	}
}

// Подпись сообщения с использованием приватного ключа
func signMessage(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(message)
	digest := hash.Sum(nil)

	// Подписываем сообщение
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Проверка подписи с использованием публичного ключа
func verifySignature(publicKey *rsa.PublicKey, message, signature []byte) error {
	hash := sha256.New()
	hash.Write(message)
	digest := hash.Sum(nil)

	// Проверяем подпись
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, signature)
	if err != nil {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func main() {
	// Шаг 1. Генерация и сохранение ключей
	err := generateKeys()
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}
	fmt.Println("Keys generated and saved to files.")

	// Шаг 2. Подготовка сообщения для подписи
	message := []byte("This is a confidential message.")

	// Шаг 3. Загрузка приватного ключа для подписания сообщения
	privateKey, err := loadPrivateKey("private_key.pem")
	if err != nil {
		fmt.Println("Error loading private key:", err)
		return
	}

	// Шаг 4. Подпись сообщения
	signature, err := signMessage(privateKey, message)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	fmt.Printf("Message signed. Signature: %x\n", signature)

	// Шаг 5. Загрузка публичного ключа для проверки подписи
	publicKey, err := loadPublicKey("public_key.pem")
	if err != nil {
		fmt.Println("Error loading public key:", err)
		return
	}

	// Шаг 6. Проверка подписи
	err = verifySignature(publicKey, message, signature)
	if err != nil {
		fmt.Println("Signature verification failed:", err)
	} else {
		fmt.Println("Signature successfully verified.")
	}

	// Демонстрация обмена сообщениями между двумя сторонами
	fmt.Println("\nSimulating message transmission between two parties:")

	// Сторона А (отправитель) подписывает сообщение
	fmt.Println("Sender (Party A) is signing the message.")
	signedMessage := signature

	// Сторона B (получатель) проверяет подпись
	fmt.Println("Receiver (Party B) is verifying the signature.")
	err = verifySignature(publicKey, message, signedMessage)
	if err != nil {
		fmt.Println("Signature verification failed:", err)
	} else {
		fmt.Println("Receiver verified the signature successfully.")
	}
}
