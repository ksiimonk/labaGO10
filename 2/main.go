package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Функция для шифрования данных с использованием AES
func encryptAES(plaintext string, key string) (string, error) {
	// Создаем блок шифра AES с ключом
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Преобразуем текст в байты
	plaintextBytes := []byte(plaintext)

	// Генерируем IV (инициализационный вектор)
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Создаем шифр потоков (CFB mode)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintextBytes)

	// Возвращаем зашифрованную строку в виде hex
	return hex.EncodeToString(ciphertext), nil
}

// Функция для расшифрования данных с использованием AES
func decryptAES(ciphertext string, key string) (string, error) {
	// Преобразуем зашифрованную строку из hex в байты
	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Создаем блок шифра AES с ключом
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Проверяем длину текста
	if len(ciphertextBytes) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Извлекаем IV из зашифрованного текста
	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	// Создаем поток расшифрования
	stream := cipher.NewCFBDecrypter(block, iv)

	// Расшифровываем данные
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

	// Возвращаем расшифрованный текст как строку
	return string(ciphertextBytes), nil
}

func main() {
	var plaintext, key string

	// Ввод строки для шифрования
	fmt.Print("Enter text to encrypt: ")
	fmt.Scanln(&plaintext)

	// Ввод секретного ключа (ключ должен быть 16, 24 или 32 байта для AES)
	fmt.Print("Enter the secret key (16, 24, or 32 characters): ")
	fmt.Scanln(&key)

	// Проверяем длину ключа
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Println("Invalid key length. Key must be 16, 24, or 32 characters long.")
		return
	}

	// Шифруем данные
	encryptedText, err := encryptAES(plaintext, key)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}
	fmt.Println("Encrypted text:", encryptedText)

	// Расшифровка
	var choice string
	fmt.Print("Do you want to decrypt the text? (yes/no): ")
	fmt.Scanln(&choice)

	if strings.ToLower(choice) == "yes" {
		// Ввод строки для расшифрования
		var encryptedInput string
		fmt.Print("Enter the encrypted text: ")
		fmt.Scanln(&encryptedInput)

		// Ввод ключа для расшифрования
		var decryptionKey string
		fmt.Print("Enter the secret key for decryption: ")
		fmt.Scanln(&decryptionKey)

		// Расшифровываем данные
		decryptedText, err := decryptAES(encryptedInput, decryptionKey)
		if err != nil {
			fmt.Println("Error decrypting:", err)
			return
		}
		fmt.Println("Decrypted text:", decryptedText)
	}
}
