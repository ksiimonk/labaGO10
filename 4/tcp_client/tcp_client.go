package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	// Адрес сервера
	serverAddress := "localhost:8443"

	// Загрузка клиентского сертификата и приватного ключа
	clientCert, err := tls.LoadX509KeyPair("client_cert.pem", "client_key.pem")
	if err != nil {
		fmt.Println("Ошибка загрузки клиентского сертификата:", err)
		os.Exit(1)
	}

	// Загрузка корневого сертификата (сертификат CA для проверки серверного сертификата)
	caCert, err := ioutil.ReadFile("ca_cert.pem")
	if err != nil {
		fmt.Println("Ошибка чтения сертификата CA:", err)
		os.Exit(1)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Настройка TLS-конфигурации с проверкой сертификата сервера
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert}, // Клиентский сертификат
		RootCAs:            caCertPool,                    // Сертификаты CA для проверки сервера
		InsecureSkipVerify: false,                         // Проверяем подлинность сервера
	}

	// Установка TLS-соединения с сервером
	conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
	if err != nil {
		fmt.Println("Ошибка при установлении TLS-соединения с сервером:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Проверка сертификата сервера после установления соединения
	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		fmt.Println("Сертификат сервера:")
		fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("  Issuer: %s\n", cert.Issuer.CommonName)
	}

	// Считываем сообщение от пользователя
	fmt.Print("Введите сообщение для отправки: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		message := scanner.Text()

		// Отправляем сообщение серверу
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Println("Ошибка при отправке сообщения:", err)
			return
		}
	}

	// Читаем ответ от сервера
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Ошибка при чтении ответа:", err)
		return
	}

	fmt.Println("Ответ от сервера:", string(buffer[:n]))
}
