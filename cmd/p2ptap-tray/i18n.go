//go:build windows
// +build windows

package main

var (
	procGetUserDefaultUILanguage = modkernel32.NewProc("GetUserDefaultUILanguage")
)

type TrayDict map[string]string

var trayI18n = map[string]TrayDict{
	"zh-CN": {
		"open_webui":       "🌐 打开 Web 控制台 (Open WebUI)",
		"speedtest":        "⚡ 运行一键 P2P 测速 (SpeedTest)",
		"copy_ip":          "📋 复制 TAP IPv4 地址",
		"copy_ipv6":        "🌐 复制 TAP IPv6 地址",
		"copy_peer":        "🔑 复制 P2P Peer ID",
		"edit_conf":        "⚙️ 编辑配置文件 (config.json)",
		"autostart_on":     "☑️ 开机自启动 (Auto-Start Enabled)",
		"autostart_off":    "☐ 开机自启动 (Auto-Start Disabled)",
		"svc_install":      "⚙️ 安装为 Windows 系统服务 (Install Service)",
		"svc_uninstall":    "⏹️ 卸载 Windows 系统服务 (Uninstall Service)",
		"set_exit_node":    "🚀 设置 Exit Node 出口网关",
		"clear_exit_node":  "⏹️ 清除 Exit Node (恢复本地网关)",
		"active_exit":      "🌐 当前 Exit Node: %s",
		"already_running":  "p2ptap 已在后台系统托盘中运行，无需重复启动！",
		"exit":             "❌ 退出 p2ptap",
		"searching_peers":  "🟡 寻找 Peers 中...",
		"peers_online":     "🟢 在线节点: %d 个 Peers",
		"realtime_speed":   "🚀 实时网速: ↑ %s  ↓ %s",
		"toast_start_head": "p2ptap P2P TAP VPN 启动成功",
		"toast_start_msg":  "节点名称: %s\nTAP IP: %s\n双击右下角图标可打开 Web 控制台！",
	},
	"zh-TW": {
		"open_webui":       "🌐 打開 Web 控制台 (Open WebUI)",
		"speedtest":        "⚡ 運行一鍵 P2P 測速 (SpeedTest)",
		"copy_ip":          "📋 複製 TAP IPv4 地址",
		"copy_ipv6":        "🌐 複製 TAP IPv6 地址",
		"copy_peer":        "🔑 複製 P2P Peer ID",
		"edit_conf":        "⚙️ 編輯設定檔 (config.json)",
		"autostart_on":     "☑️ 開機自啟動 (Auto-Start Enabled)",
		"autostart_off":    "☐ 開機自啟動 (Auto-Start Disabled)",
		"svc_install":      "⚙️ 安裝為 Windows 系統服務 (Install Service)",
		"svc_uninstall":    "⏹️ 解除安裝 Windows 系統服務 (Uninstall Service)",
		"set_exit_node":    "🚀 設定 Exit Node 出口網關",
		"clear_exit_node":  "⏹️ 清除 Exit Node (恢復本地網關)",
		"active_exit":      "🌐 當前 Exit Node: %s",
		"already_running":  "p2ptap 已在後台系統托盤中運行，無需重複啟動！",
		"exit":             "❌ 退出 p2ptap",
		"searching_peers":  "🟡 尋找 Peers 中...",
		"peers_online":     "🟢 在線節點: %d 個 Peers",
		"realtime_speed":   "🚀 實時網速: ↑ %s  ↓ %s",
		"toast_start_head": "p2ptap P2P TAP VPN 啟動成功",
		"toast_start_msg":  "節點名稱: %s\nTAP IP: %s\n雙擊右下角圖示可打開 Web 控制台！",
	},
	"en": {
		"open_webui":       "🌐 Open Web Console (WebUI)",
		"speedtest":        "⚡ Run P2P SpeedTest",
		"copy_ip":          "📋 Copy TAP IPv4 Address",
		"copy_ipv6":        "🌐 Copy TAP IPv6 Address",
		"copy_peer":        "🔑 Copy P2P Peer ID",
		"edit_conf":        "⚙️ Edit Config (config.json)",
		"autostart_on":     "☑️ Auto-Start on Boot (Enabled)",
		"autostart_off":    "☐ Auto-Start on Boot (Disabled)",
		"svc_install":      "⚙️ Install as Windows System Service",
		"svc_uninstall":    "⏹️ Uninstall Windows System Service",
		"set_exit_node":    "🚀 Set Exit Node Gateway",
		"clear_exit_node":  "⏹️ Clear Exit Node (Restore Default Gateway)",
		"active_exit":      "🌐 Active Exit Node: %s",
		"already_running":  "p2ptap is already running in the system tray!",
		"exit":             "❌ Exit p2ptap",
		"searching_peers":  "🟡 Searching for Peers...",
		"peers_online":     "🟢 %d Peers Online",
		"realtime_speed":   "🚀 Speed: ↑ %s  ↓ %s",
		"toast_start_head": "p2ptap P2P TAP VPN Started",
		"toast_start_msg":  "Node Name: %s\nTAP IP: %s\nDouble-click tray icon to open WebUI!",
	},
	"ja": {
		"open_webui":       "🌐 Webダッシュボードを開く",
		"speedtest":        "⚡ P2Pスピードテスト実行",
		"copy_ip":          "📋 TAP仮想IPをコピー",
		"copy_peer":        "🔑 P2P Peer IDをコピー",
		"edit_conf":        "⚙️ 設定ファイルを編集 (config.json)",
		"autostart_on":     "☑️ 自動起動 (有効)",
		"autostart_off":    "☐ 自動起動 (無効)",
		"svc_install":      "⚙️ Windowsシステムサービスとしてインストール",
		"svc_uninstall":    "⏹️ Windowsシステムサービスを削除",
		"set_exit_node":    "🚀 Exit Node（出口ゲートウェイ）を設定",
		"clear_exit_node":  "⏹️ Exit Nodeを解除 (元に戻す)",
		"active_exit":      "🌐 現在のExit Node: %s",
		"already_running":  "p2ptapは既にシステムトレイで実行中です！",
		"exit":             "❌ p2ptapを終了",
		"searching_peers":  "🟡 Peerを検索中...",
		"peers_online":     "🟢 オンラインPeer: %d 台",
		"realtime_speed":   "🚀 リアルタイム速度: ↑ %s  ↓ %s",
		"toast_start_head": "p2ptap P2P TAP VPN 起動完了",
		"toast_start_msg":  "ノード名: %s\nTAP IP: %s\nトレイアイコンをダブルクリックでWebUI表示",
	},
	"de": {
		"open_webui":       "🌐 Web-Konsole öffnen (WebUI)",
		"speedtest":        "⚡ P2P-Geschwindigkeitstest ausführen",
		"copy_ip":          "📋 Virtuelle TAP-IP kopieren",
		"copy_peer":        "🔑 P2P-Peer-ID kopieren",
		"edit_conf":        "⚙️ Konfigurationsdatei bearbeiten (config.json)",
		"autostart_on":     "☑️ Autostart beim Booten (Aktiviert)",
		"autostart_off":    "☐ Autostart beim Booten (Deaktiviert)",
		"svc_install":      "⚙️ Als Windows-Dienst installieren",
		"svc_uninstall":    "⏹️ Windows-Dienst deinstallieren",
		"set_exit_node":    "🚀 Exit-Node Gateway festlegen",
		"clear_exit_node":  "⏹️ Exit-Node entfernen (Standard wiederherstellen)",
		"active_exit":      "🌐 Aktiver Exit-Node: %s",
		"already_running":  "p2ptap läuft bereits im System-Tray!",
		"exit":             "❌ p2ptap Beenden",
		"searching_peers":  "🟡 Suche nach Peers...",
		"peers_online":     "🟢 %d Peers Online",
		"realtime_speed":   "🚀 Geschwindigkeit: ↑ %s  ↓ %s",
		"toast_start_head": "p2ptap P2P TAP VPN Gestartet",
		"toast_start_msg":  "Knotenname: %s\nTAP-IP: %s\nDoppelklick auf das Symbol zum Öffnen!",
	},
	"es": {
		"open_webui":       "🌐 Abrir Consola Web (WebUI)",
		"speedtest":        "⚡ Ejecutar Prueba de Velocidad P2P",
		"copy_ip":          "📋 Copiar IP Virtual TAP",
		"copy_peer":        "🔑 Copiar ID de Peer P2P",
		"edit_conf":        "⚙️ Editar Configuración (config.json)",
		"autostart_on":     "☑️ Inicio Automático (Activado)",
		"autostart_off":    "☐ Inicio Automático (Desactivado)",
		"svc_install":      "⚙️ Instalar como Servicio de Windows",
		"svc_uninstall":    "⏹️ Desinstalar Servicio de Windows",
		"set_exit_node":    "🚀 Establecer Exit Node Gateway",
		"clear_exit_node":  "⏹️ Quitar Exit Node (Restaurar predeterminado)",
		"active_exit":      "🌐 Exit Node Activo: %s",
		"already_running":  "¡p2ptap ya se está ejecutando en la bandeja del sistema!",
		"exit":             "❌ Salir de p2ptap",
		"searching_peers":  "🟡 Buscando Peers...",
		"peers_online":     "🟢 %d Peers En Línea",
		"realtime_speed":   "🚀 Velocidad: ↑ %s  ↓ %s",
		"toast_start_head": "p2ptap P2P TAP VPN Iniciado",
		"toast_start_msg":  "Nombre de Nodo: %s\nIP TAP: %s\n¡Doble clic en el icono para abrir!",
	},
	"fr": {
		"open_webui":       "🌐 Ouvrir la Console Web (WebUI)",
		"speedtest":        "⚡ Exécuter le Test de Débit P2P",
		"copy_ip":          "📋 Copier l'IP Virtuelle TAP",
		"copy_peer":        "🔑 Copier l'ID du Peer P2P",
		"edit_conf":        "⚙️ Modifier la Configuration (config.json)",
		"autostart_on":     "☑️ Démarrage Automatique (Activé)",
		"autostart_off":    "☐ Démarrage Automatique (Désactivé)",
		"svc_install":      "⚙️ Installer comme Service Windows",
		"svc_uninstall":    "⏹️ Désinstaller le Service Windows",
		"set_exit_node":    "🚀 Définir la Passerelle Exit Node",
		"clear_exit_node":  "⏹️ Supprimer l'Exit Node (Restaurer la passerelle)",
		"active_exit":      "🌐 Exit Node Actif: %s",
		"already_running":  "p2ptap est déjà en cours d'exécution dans la barre des tâches !",
		"exit":             "❌ Quitter p2ptap",
		"searching_peers":  "🟡 Recherche de Peers...",
		"peers_online":     "🟢 %d Peers En Ligne",
		"realtime_speed":   "🚀 Débit: ↑ %s  ↓ %s",
		"toast_start_head": "p2ptap P2P TAP VPN Démarré",
		"toast_start_msg":  "Nom du Nœud: %s\nIP TAP: %s\nDouble-cliquez sur l'icône pour ouvrir !",
	},
}

var currentLang = "en"

func initTrayI18n() {
	langID, _, _ := procGetUserDefaultUILanguage.Call()
	switch langID & 0xffff {
	case 0x0804:
		currentLang = "zh-CN"
	case 0x0404, 0x0c04, 0x1404:
		currentLang = "zh-TW"
	case 0x0411:
		currentLang = "ja"
	case 0x0407:
		currentLang = "de"
	case 0x040a, 0x0c0a, 0x100a, 0x140a:
		currentLang = "es"
	case 0x040c, 0x080c, 0x0c0c:
		currentLang = "fr"
	default:
		currentLang = "en"
	}
}

func tT(key string) string {
	if dict, ok := trayI18n[currentLang]; ok {
		if val, ok := dict[key]; ok {
			return val
		}
	}
	if dict, ok := trayI18n["en"]; ok {
		if val, ok := dict[key]; ok {
			return val
		}
	}
	return key
}
