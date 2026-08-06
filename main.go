//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	_ "embed" // <--- Обязательно добавьте нижнее подчеркивание перед "embed"!
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
	"golang.org/x/sys/windows"
)

// Вшиваем инсталлятор драйвера прямо внутри .exe
//
//go:embed tap-installer.exe
var tapInstallerBytes []byte

// Вшиваем HTML-интерфейс
//
//go:embed index.html
var htmlUI string

const (
	FrameSize  = 1514                            // MTU обычного Ethernet-кадра
	udpPort    = 1194                            // UDP-порт для передачи трафика
	nonceSize  = 12                              // Размер nonce для AES-GCM
	udpBufSize = FrameSize + nonceSize + 16 + 64 // запас под тег и заголовки
)

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
	gcm         cipher.AEAD
	stopCh      chan struct{}
}

var manager = &TunnelManager{
	publicIP: "Определяем...",
}

func main() {
	// 0. Гарантируем, что приложение запущено с правами администратора —
	// без них не встанет TAP-драйвер и не сработает настройка IP/файрвола.
	if !isAdmin() {
		if err := relaunchAsAdmin(); err == nil {
			os.Exit(0)
		}
		log.Println("[!] Не удалось перезапуститься с правами администратора, продолжаем без них")
	}

	// 0.1 Не даём запустить вторую копию приложения одновременно
	if !ensureSingleInstance() {
		log.Println("[!] MCTunnel уже запущен")
		os.Exit(0)
	}

	// 1. Автоматически определяем наш публичный IP
	go manager.fetchPublicIP()

	// 2. Открываем в системном файрволе UDP-порт туннеля
	go ensureFirewallRule()

	// 3. Запускаем локальный веб-сервер для GUI
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/start", handleStart)
	http.HandleFunc("/api/stop", handleStop)
	http.HandleFunc("/api/quit", handleQuit)

	listener, err := net.Listen("tcp", "127.0.0.1:0") // Динамический свободный порт
	if err != nil {
		log.Fatalf("Не удалось запустить GUI: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	guiURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// 4. Открываем интерфейс в отдельном автономном окне (App Mode)
	go openGUIWindow(guiURL)

	// 5. Корректно останавливаем туннель при закрытии процесса (Ctrl+C, taskkill и т.п.)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		manager.Stop()
		os.Exit(0)
	}()

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
	log.Println(msg)
}

// Запуск туннеля из GUI
func (tm *TunnelManager) Start(mode, peerIP, roomCode string) error {
	tm.mu.Lock()
	if tm.running {
		tm.mu.Unlock()
		return fmt.Errorf("туннель уже запущен")
	}
	tm.mu.Unlock()

	if net.ParseIP(peerIP) == nil {
		return fmt.Errorf("некорректный IP-адрес друга: %s", peerIP)
	}
	if strings.TrimSpace(roomCode) == "" {
		return fmt.Errorf("укажите код комнаты (пароль) — без него туннель не шифруется")
	}

	tm.mu.Lock()
	tm.mode = mode
	tm.peerIP = peerIP
	tm.mu.Unlock()

	// Ключ шифрования — SHA-256 от кода комнаты, известного только участникам
	key := sha256.Sum256([]byte(roomCode))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("ошибка инициализации шифра: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("ошибка инициализации GCM: %w", err)
	}

	tm.addLog("Проверка и установка TAP-драйвера...")
	if err := ensureTAPDriver(); err != nil {
		tm.addLog(fmt.Sprintf("Предупреждение: установка TAP-драйвера завершилась с ошибкой: %v", err))
	}

	virtualIP := "10.0.0.1"
	if mode == "client" {
		virtualIP = "10.0.0.2"
	}

	config := water.Config{DeviceType: water.TAP}
	config.ComponentID = "tap0901"

	tapDev, err := water.New(config)
	if err != nil {
		tm.addLog(fmt.Sprintf("ОШИБКА открытия TAP: %v", err))
		return err
	}

	adapterName := tapDev.Name()
	tm.addLog(fmt.Sprintf("Открыт адаптер: %s", adapterName))

	// Настройка IP через netsh
	tm.addLog(fmt.Sprintf("Настройка IP-адреса %s...", virtualIP))
	if err := configureIP(adapterName, virtualIP); err != nil {
		tm.addLog(fmt.Sprintf("Предупреждение: не удалось настроить IP автоматически: %v", err))
	}

	// Сокет UDP
	localAddr := fmt.Sprintf("0.0.0.0:%d", udpPort)
	remoteAddr := fmt.Sprintf("%s:%d", peerIP, udpPort)

	lAddr, err := net.ResolveUDPAddr("udp4", localAddr)
	if err != nil {
		tapDev.Close()
		return fmt.Errorf("не удалось разобрать локальный адрес: %w", err)
	}
	rAddr, err := net.ResolveUDPAddr("udp4", remoteAddr)
	if err != nil {
		tapDev.Close()
		return fmt.Errorf("не удалось разобрать адрес друга: %w", err)
	}

	udpConn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		tm.addLog(fmt.Sprintf("ОШИБКА открытия UDP (порт %d занят?): %v", udpPort, err))
		tapDev.Close()
		return err
	}

	stopCh := make(chan struct{})

	tm.mu.Lock()
	tm.running = true
	tm.virtualIP = virtualIP
	tm.adapterName = adapterName
	tm.tapDev = tapDev
	tm.udpConn = udpConn
	tm.gcm = gcm
	tm.stopCh = stopCh
	tm.mu.Unlock()

	tm.addLog(fmt.Sprintf("🚀 Туннель активен! Ваш виртуальный IP: %s", virtualIP))

	// Горутина 1: Чтение TAP -> Шифрование -> Отправка UDP
	go func() {
		buf := make([]byte, FrameSize)
		// nonce получает запасную ёмкость, чтобы Seal дописывал шифротекст
		// в тот же буфер без повторной аллокации на каждый пакет
		nonce := make([]byte, nonceSize, udpBufSize)
		for {
			n, err := tapDev.Read(buf)
			if err != nil {
				return // Адаптер закрыт
			}
			if n == 0 {
				continue
			}
			if _, err := rand.Read(nonce[:nonceSize]); err != nil {
				continue
			}
			out := gcm.Seal(nonce[:nonceSize], nonce[:nonceSize], buf[:n], nil)
			if _, err := udpConn.WriteToUDP(out, rAddr); err != nil {
				select {
				case <-stopCh:
					return
				default:
				}
			}
		}
	}()

	// Горутина 2: Прием UDP -> Расшифровка -> Запись TAP
	go func() {
		buf := make([]byte, udpBufSize)
		var lastBadLog time.Time
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return // Сокет закрыт
			}
			if addr.IP.String() != rAddr.IP.String() {
				continue // трафик не от нашего собеседника — игнорируем
			}
			if n < nonceSize {
				continue
			}
			plain, err := gcm.Open(nil, buf[:nonceSize], buf[nonceSize:n], nil)
			if err != nil {
				// Неверный код комнаты у собеседника или чужой/повреждённый пакет
				if time.Since(lastBadLog) > 5*time.Second {
					tm.addLog("⚠ Получен пакет, который не удалось расшифровать (проверьте код комнаты)")
					lastBadLog = time.Now()
				}
				continue
			}
			tapDev.Write(plain)
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

	if tm.stopCh != nil {
		close(tm.stopCh)
	}
	if tm.tapDev != nil {
		tm.tapDev.Close()
	}
	if tm.udpConn != nil {
		tm.udpConn.Close()
	}

	tm.running = false
	tm.addLogLocked("🛑 Туннель остановлен.")
}

// addLogLocked — то же самое, что addLog, но вызывается когда tm.mu уже захвачен
func (tm *TunnelManager) addLogLocked(msg string) {
	timestamp := time.Now().Format("15:04:05")
	tm.logs = append(tm.logs, fmt.Sprintf("[%s] %s", timestamp, msg))
	if len(tm.logs) > 50 {
		tm.logs = tm.logs[1:]
	}
	log.Println(msg)
}

// Вспомогательные функции
func ensureTAPDriver() error {
	tempDir := os.TempDir()
	installerPath := filepath.Join(tempDir, "tap-installer-tmp.exe")
	if err := os.WriteFile(installerPath, tapInstallerBytes, 0755); err != nil {
		return err
	}
	defer os.Remove(installerPath)

	cmd := exec.Command(installerPath, "/S")
	if err := cmd.Run(); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	return nil
}

func configureIP(adapterName, ip string) error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", adapterName),
		"static", ip, "255.255.255.0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Открывает входящий UDP-порт туннеля в брандмауэре Windows (один раз)
func ensureFirewallRule() {
	const ruleName = "MCTunnel UDP"
	check := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	out, _ := check.CombinedOutput()
	if strings.Contains(string(out), ruleName) {
		return // правило уже существует
	}
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName, "dir=in", "action=allow", "protocol=UDP",
		fmt.Sprintf("localport=%d", udpPort)).Run()
}

func openGUIWindow(url string) {
	// Пробуем открыть в автономном окне Edge (App Mode)
	cmd := exec.Command("msedge", "--app="+url)
	if err := cmd.Start(); err != nil {
		// Если не вышло — открываем в стандартном браузере
		exec.Command("cmd", "/c", "start", url).Run()
	}
}

// Проверка прав администратора
func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// Перезапуск процесса с запросом повышения прав (UAC)
func relaunchAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exe)
	cwdPtr, _ := windows.UTF16PtrFromString(cwd)
	argPtr, _ := windows.UTF16PtrFromString(args)

	return windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, windows.SW_NORMAL)
}

// Не позволяет запустить вторую копию приложения одновременно
func ensureSingleInstance() bool {
	namePtr, err := windows.UTF16PtrFromString("Global\\MCTunnelSingleInstanceMutex")
	if err != nil {
		return true // не смогли проверить — не блокируем запуск
	}
	_, err = windows.CreateMutex(nil, false, namePtr)
	if err == windows.ERROR_ALREADY_EXISTS {
		return false
	}
	return true
}

// HTTP Обработчики
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, htmlUI)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"running":    manager.running,
		"public_ip":  manager.publicIP,
		"virtual_ip": manager.virtualIP,
		"logs":       manager.logs,
	})
}

func handleStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode     string `json:"mode"`
		PeerIP   string `json:"peer_ip"`
		RoomCode string `json:"room_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Некорректный запрос", 400)
		return
	}

	if req.PeerIP == "" {
		http.Error(w, "Укажите IP друга", 400)
		return
	}

	if err := manager.Start(req.Mode, req.PeerIP, req.RoomCode); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(200)
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	manager.Stop()
	w.WriteHeader(200)
}

// Полностью завершает работу приложения (кнопка "Выход" в GUI)
func handleQuit(w http.ResponseWriter, r *http.Request) {
	manager.Stop()
	w.WriteHeader(200)
	go func() {
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	}()
}
