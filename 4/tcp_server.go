package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var wg sync.WaitGroup

func main() {
	port := ":8443"

	// Загрузка серверного сертификата и приватного ключа
	cert, err := tls.LoadX509KeyPair("C:/dev/projects/labPP7/1to3/server_cert.pem", "C:/dev/projects/labPP7/1to3/server_key.pem")
	if err != nil {
		fmt.Println("Ошибка загрузки сертификатов:", err)
		os.Exit(1)
	}

	// Загрузка корневого сертификата для проверки клиентских сертификатов
	clientCACert, err := ioutil.ReadFile("C:/dev/projects/labPP7/1to3/ca_cert.pem")
	if err != nil {
		fmt.Println("Ошибка чтения сертификата CA:", err)
		os.Exit(1)
	}
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	// Настройка TLS-конфигурации
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},        // Сертификат сервера
		ClientCAs:    clientCertPool,                 // Сертификаты CA для проверки клиента
		ClientAuth:   tls.RequireAndVerifyClientCert, // Обязательная проверка клиентских сертификатов
	}

	// Создаем слушатель TLS
	listener, err := tls.Listen("tcp", port, tlsConfig)
	if err != nil {
		fmt.Println("Ошибка при запуске TLS-сервера:", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("TLS-сервер запущен на порту", port)

	// Канал для сигналов
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-done
		fmt.Println("\nЗавершение работы сервера...")
		listener.Close() // Закрываем слушатель
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Проверяем, был ли сервер закрыт
			if ne, ok := err.(*net.OpError); ok && ne.Op == "accept" {
				break // Выход из цикла, если сервер закрыт
			}
			fmt.Println("Ошибка при приеме соединения:", err)
			continue
		}
		wg.Add(1) // Увеличиваем счётчик горутин
		go handleConnection(conn)
	}

	wg.Wait() // Ожидаем завершения всех горутин
	fmt.Println("Все соединения завершены. Сервер остановлен.")
}

// Обработка соединений с клиентом
func handleConnection(conn net.Conn) {
	defer wg.Done()    // Уменьшаем счётчик горутин
	defer conn.Close() // Закрываем соединение после завершения обработки

	// Проверка, является ли соединение TLS-соединением
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		// Рукопожатие TLS (Handshake)
		err := tlsConn.Handshake()
		if err != nil {
			fmt.Println("Ошибка TLS рукопожатия:", err)
			return
		}

		// Получение информации о клиенте
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			clientCert := state.PeerCertificates[0]
			fmt.Println("Клиентское соединение установлено с:", clientCert.Subject.CommonName)
		} else {
			fmt.Println("Не удалось получить клиентский сертификат.")
			return
		}
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Ошибка при чтении данных:", err)
		return
	}

	message := string(buffer[:n])
	fmt.Println("Получено сообщение:", message)

	confirmation := "Сообщение получено"
	_, err = conn.Write([]byte(confirmation))
	if err != nil {
		fmt.Println("Ошибка при отправке данных:", err)
		return
	}
}
