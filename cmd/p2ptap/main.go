package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"


	"github.com/libp2p/go-libp2p/core/crypto"

	"p2ptap/cmd/internal/bootstrap"
	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/node"
	"p2ptap/pkg/version"
)

func main() {
	if checkAndRunService() {
		return
	}

	if len(os.Args) < 2 {
		printUsage()
		runDefaultNode("config.json")
		return
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "service":
		handleServiceCommand(os.Args[2:])

	case "genconf":
		genconfFlags := flag.NewFlagSet("genconf", flag.ExitOnError)
		outputFile := genconfFlags.String("o", "config.json", "Output config file path")
		_ = genconfFlags.Parse(os.Args[2:])
		generateConfigFile(*outputFile)

	case "run":
		runFlags := flag.NewFlagSet("run", flag.ExitOnError)
		configFile := runFlags.String("c", "config.json", "Path to config file")
		_ = runFlags.Parse(os.Args[2:])
		runDefaultNode(*configFile)

	case "version", "-v", "--version", "-version":
		fmt.Println(version.Full())

	case "-c":
		// Direct flag execution: p2ptap -c config.json
		cfg, configPath, err := config.ParseFlagsAndLoadConfig(os.Args[1:])
		if err != nil {
			fmt.Printf("Error loading configuration (%s): %v\n", configPath, err)
			os.Exit(1)
		}
		startNode(cfg)

	default:
		fmt.Printf("Unknown command '%s'\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: p2ptap <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  run        Run P2P TAP VPN node using config file")
	fmt.Println("             Example: p2ptap run -c config.json")
	fmt.Println("  service    Manage Windows Service (install, uninstall, start, stop, status)")
	fmt.Println("             Example: p2ptap service install -c config.json")
	fmt.Println("  genconf    Generate default config.json file with random MAC, PSK & persistent node.key")
	fmt.Println("             Example: p2ptap genconf -o config.json")
	fmt.Println("  version    Display version information")
	fmt.Println()
}


func generateConfigFile(outPath string) {
	absOutPath, err := filepath.Abs(outPath)
	if err != nil {
		absOutPath = outPath
	}

	configDir := filepath.Dir(absOutPath)
	keyFilePath := filepath.Join(configDir, "node.key")

	// 1. Generate persistent identity key in same directory
	privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err == nil {
		keyBytes, err := crypto.MarshalPrivateKey(privKey)
		if err == nil {
			_ = os.MkdirAll(configDir, 0755)
			if err := os.WriteFile(keyFilePath, keyBytes, 0600); err == nil {
				fmt.Printf("[+] Generated persistent identity key: %s\n", keyFilePath)
			}
		}
	}

	// 2. Generate random locally administered unicast MAC address (02:xx:xx:xx:xx:xx)
	macBuf := make([]byte, 5)
	_, _ = rand.Read(macBuf)
	randomMAC := fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", macBuf[0], macBuf[1], macBuf[2], macBuf[3], macBuf[4])

	// 3. Generate random 32-byte (256-bit) PSK
	pskBuf := make([]byte, 32)
	_, _ = rand.Read(pskBuf)
	randomPSK := hex.EncodeToString(pskBuf)

	cfg := config.DefaultConfig()
	cfg.TapMAC = randomMAC
	cfg.PSK = randomPSK
	cfg.NodeKeyFile = keyFilePath

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Printf("Error serializing config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(absOutPath, data, 0644); err != nil {
		fmt.Printf("Error writing config file %s: %v\n", absOutPath, err)
		os.Exit(1)
	}

	fmt.Printf("[+] Successfully generated configuration file: %s\n", absOutPath)
	fmt.Printf("    - Node Name  : %s\n", cfg.NodeName)
	fmt.Printf("    - Random MAC : %s\n", randomMAC)
	fmt.Printf("    - Random PSK : %s\n", randomPSK)
	fmt.Printf("    - Node Key   : %s\n", keyFilePath)
}

func runDefaultNode(configPath string) {
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		fmt.Printf("Error loading configuration (%s): %v\n", configPath, err)
		fmt.Println("Tip: Run 'p2ptap genconf' to generate a default config.json file.")
		os.Exit(1)
	}
	startNode(cfg)
}

func startNode(cfg *config.Config) {
	// Ensure only one p2ptap daemon or service instance is running
	hMutex, isSingle := acquireDaemonMutex("p2ptap_Daemon_SingleInstance_Mutex")
	if !isSingle {
		fmt.Println("[-] Another p2ptap instance (or Windows Service) is already running. Exiting.")
		os.Exit(1)
	}
	defer releaseDaemonMutex(hMutex)

	// Initialize global log level from config
	logger.SetGlobalLevel(logger.ParseLevel(cfg.LogLevel))


	log := logger.New("Main")
	log.Info("Log level set to: %s", cfg.LogLevel)

	n, _, initErr := bootstrap.Node(cfg)
	if n == nil {
		fmt.Printf("Error initializing P2P node: %v\n", initErr)
		os.Exit(1)
	}
	if initErr != nil {
		log.Error("Failed to setup WebUI: %v", initErr)
	}

	n.Start()
	node.PrintBanner(n)

	// Wait for shutdown signal (SIGINT / SIGTERM)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutdown signal received, closing node...")
	_ = n.Close()
	log.Info("Node stopped cleanly.")
}

