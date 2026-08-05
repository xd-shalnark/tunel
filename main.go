package main

import (
	_ "embed" // <--- Обязательно добавьте нижнее подчеркивание перед "embed"!
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/songgao/water"
)

// Вшиваем инсталлятор драйвера прямо внутри .exe
//
//go:embed tap-installer.exe
var tapInstallerBytes []byte

// Вшиваем HTML-интерфейс
//
//go:embed index.html
var htmlUI string

const FrameSize = 1514

type TunnelManager struct {
	mu          sync.Mutex
	running     bool
	virtualIP   string
	peerIP      string
	mode        string
	logs        []string
	publicIP    string
	adapterName string
	tapDev      *water.Interface
	udpConn     *net.UDPConn
}

var manager = &TunnelManager{
	publicIP: "Определяем...",
}

func main() {
	// 1. Автоматически определяем наш публичный IP
	go manager.fetchPublicIP()

	// 2. Запускаем локальный веб-сервер для GUI
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/start", handleStart)
	http.HandleFunc("/api/stop", handleStop)

	listener, err := net.Listen("tcp", "127.0.0.1:0") // Динамический свободный порт
	if err != nil {
		log.Fatalf("Не удалось запустить GUI: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	guiURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// 3. Открываем интерфейс в отдельном автономном окне (App Mode)
	go openGUIWindow(guiURL)

	log.Printf("[+] GUI запущен на %s\n", guiURL)
	http.Serve(listener, nil)
}

// Запрос внешнего IP через публичный API
func (tm *TunnelManager) fetchPublicIP() {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			tm.mu.Lock()
			tm.publicIP = string(body)
			tm.mu.Unlock()
			return
		}
	}
	tm.mu.Lock()
	tm.publicIP = "Не удалось определить"
	tm.mu.Unlock()
}

func (tm *TunnelManager) addLog(msg string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	timestamp := time.Now().Format("15:04:05")
	tm.logs = append(tm.logs, fmt.Sprintf("[%s] %s", timestamp, msg))
	if len(tm.logs) > 50 {
		tm.logs = tm.logs[1:]
	}
}

// Запуск туннеля из GUI
func (tm *TunnelManager) Start(mode, peerIP string) error {
	tm.mu.Lock()
	if tm.running {
		tm.mu.Unlock()
		return fmt.Errorf("туннель уже запущен")
	}
	tm.mode = mode
	tm.peerIP = peerIP
	tm.mu.Unlock()

	tm.addLog("Проверка и установка TAP-драйвера...")
	ensureTAPDriver()

	virtualIP := "10.0.0.1"
	if mode == "client" {
		virtualIP = "10.0.0.2"
	}
	tm.virtualIP = virtualIP

	config := water.Config{DeviceType: water.TAP}
	config.ComponentID = "tap0901"

	tapDev, err := water.New(config)
	if err != nil {
		tm.addLog(fmt.Sprintf("ОШИБКА открытия TAP: %v", err))
		return err
	}

	tm.adapterName = tapDev.Name()
	tm.addLog(fmt.Sprintf("Открыт адаптер: %s", tm.adapterName))

	// Настройка IP через netsh
	tm.addLog(fmt.Sprintf("Настройка IP-адреса %s...", virtualIP))
	configureIP(tm.adapterName, virtualIP)

	// Сокет UDP
	localAddr := "0.0.0.0:1194"
	remoteAddr := fmt.Sprintf("%s:1194", peerIP)

	lAddr, _ := net.ResolveUDPAddr("udp4", localAddr)
	rAddr, _ := net.ResolveUDPAddr("udp4", remoteAddr)

	udpConn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		tm.addLog(fmt.Sprintf("ОШИБКА открытия UDP: %v", err))
		tapDev.Close()
		return err
	}

	tm.mu.Lock()
	tm.running = true
	tm.tapDev = tapDev
	tm.udpConn = udpConn
	tm.mu.Unlock()

	tm.addLog(fmt.Sprintf("🚀 Туннель активен! Ваш виртуальный IP: %s", virtualIP))

	// Горутина 1: Чтение TAP -> Отправка UDP
	go func() {
		buf := make([]byte, FrameSize)
		for {
			n, err := tapDev.Read(buf)
			if err != nil {
				return // Адаптер закрыт
			}
			if n > 0 {
				udpConn.WriteToUDP(buf[:n], rAddr)
			}
		}
	}()

	// Горутина 2: Прием UDP -> Запись TAP
	go func() {
		buf := make([]byte, FrameSize)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return // Сокет закрыт
			}
			if addr.IP.String() == rAddr.IP.String() {
				tapDev.Write(buf[:n])
			}
		}
	}()

	return nil
}

func (tm *TunnelManager) Stop() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if !tm.running {
		return
	}

	if tm.tapDev != nil {
		tm.tapDev.Close()
	}
	if tm.udpConn != nil {
		tm.udpConn.Close()
	}

	tm.running = false
	tm.addLog("🛑 Туннель остановлен.")
}

// Вспомогательные функции
func ensureTAPDriver() {
	tempDir := os.TempDir()
	installerPath := filepath.Join(tempDir, "tap-installer-tmp.exe")
	_ = os.WriteFile(installerPath, tapInstallerBytes, 0755)
	defer os.Remove(installerPath)

	cmd := exec.Command(installerPath, "/S")
	_ = cmd.Run()
	time.Sleep(2 * time.Second)
}

func configureIP(adapterName, ip string) {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", adapterName),
		"static", ip, "255.255.255.0")
	_ = cmd.Run()
}

func openGUIWindow(url string) {
	// Пробуем открыть в автономном окне Edge (App Mode)
	cmd := exec.Command("msedge", "--app="+url)
	if err := cmd.Start(); err != nil {
		// Если не вышло — открываем в стандартном браузере
		exec.Command("cmd", "/c", "start", url).Run()
	}
}

// HTTP Обработчики
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, htmlUI)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"running":    manager.running,
		"public_ip":  manager.publicIP,
		"virtual_ip": manager.virtualIP,
		"logs":       manager.logs,
	})
}

func handleStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode   string `json:"mode"`
		PeerIP string `json:"peer_ip"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.PeerIP == "" {
		http.Error(w, "Укажите IP друга", 400)
		return
	}

	err := manager.Start(req.Mode, req.PeerIP)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	manager.Stop()
	w.WriteHeader(200)
}
