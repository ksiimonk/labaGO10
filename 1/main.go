package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strings"
)

// Функция для вычисления хэша на основе выбранного алгоритма
func computeHash(algorithm string, input string) (string, error) {
	var hasher hash.Hash

	switch algorithm {
	case "MD5":
		hasher = md5.New()
	case "SHA-256":
		hasher = sha256.New()
	case "SHA-512":
		hasher = sha512.New()
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Записываем данные в хэш-объект
	hasher.Write([]byte(input))

	// Возвращаем строковое представление хэша в шестнадцатеричном формате
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Функция для проверки целостности данных
func verifyIntegrity(algorithm, input, providedHash string) (bool, error) {
	calculatedHash, err := computeHash(algorithm, input)
	if err != nil {
		return false, err
	}

	// Сравниваем введенный хэш с вычисленным
	return calculatedHash == strings.ToLower(providedHash), nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Ввод строки для хэширования
	fmt.Print("Enter the string to hash: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	// Выбор алгоритма хэширования
	fmt.Print("Choose hash algorithm (MD5, SHA-256, SHA-512): ")
	algorithm, _ := reader.ReadString('\n')
	algorithm = strings.TrimSpace(strings.ToUpper(algorithm))

	// Вычисляем хэш
	hashValue, err := computeHash(algorithm, input)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Hash (%s): %s\n", algorithm, hashValue)

	// Проверка целостности данных
	fmt.Print("Do you want to verify the hash? (yes/no): ")
	verifyChoice, _ := reader.ReadString('\n')
	verifyChoice = strings.TrimSpace(strings.ToLower(verifyChoice))

	if verifyChoice == "yes" {
		fmt.Print("Enter the hash to verify: ")
		providedHash, _ := reader.ReadString('\n')
		providedHash = strings.TrimSpace(providedHash)

		// Проверяем соответствие хэша
		match, err := verifyIntegrity(algorithm, input, providedHash)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if match {
			fmt.Println("The hash matches!")
		} else {
			fmt.Println("The hash does not match.")
		}
	}
}
