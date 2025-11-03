package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// exitCheck can be deferred from the top of command functions to exit with an
// error code after any other defers are run in the same scope.
func exitCheck(err error) {
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
}

// bootResources tracks resources that need cleanup
type bootResources struct {
	qemuCmd     *exec.Cmd
	dnsmasqCmd  *exec.Cmd
	httpCmd     *exec.Cmd
	tapDevice   string
	workdir     string
	dnsmasqConf string
}

// cleanup tears down all boot resources
func (r *bootResources) cleanup() {
	if r.qemuCmd != nil && r.qemuCmd.Process != nil {
		fmt.Println("🧹 Stopping QEMU")
		r.qemuCmd.Process.Kill()
	}
	if r.dnsmasqCmd != nil && r.dnsmasqCmd.Process != nil {
		fmt.Println("🧹 Stopping dnsmasq")
		r.dnsmasqCmd.Process.Kill()
	}
	if r.httpCmd != nil && r.httpCmd.Process != nil {
		fmt.Println("🧹 Stopping HTTP server")
		r.httpCmd.Process.Kill()
	}
	if r.tapDevice != "" {
		fmt.Printf("🧹 Removing tap device %s\n", r.tapDevice)
		cmd := exec.Command("sudo", "ip", "tuntap", "del", "mode", "tap", r.tapDevice)
		cmd.Run()
	}
	if r.dnsmasqConf != "" {
		os.Remove(r.dnsmasqConf)
	}
}

// setupTapDevice creates and configures a tap network device
func setupTapDevice(name string) error {
	fmt.Printf("🌐 Creating tap device %s\n", name)
	cmd := exec.Command("sudo", "ip", "tuntap", "add", "mode", "tap", "user", "root", "name", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create tap device: %w", err)
	}

	cmd = exec.Command("sudo", "ip", "link", "set", "dev", name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up tap device: %w", err)
	}

	cmd = exec.Command("sudo", "ip", "addr", "add", "192.168.128.1/24", "dev", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure tap device IP: %w", err)
	}

	return nil
}

// generateDnsmasqConfig creates a dnsmasq config file for the specified mode
func generateDnsmasqConfig(mode string, tftpRoot string) (string, error) {
	f, err := os.CreateTemp("", "dnsmasq-*.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()

	base := `port=0
interface=tap0
dhcp-range=192.168.128.100,192.168.128.200,255.255.255.0,1h
`
	if _, err := f.WriteString(base); err != nil {
		return "", err
	}

	switch mode {
	case "pxe-bios":
		config := fmt.Sprintf(`enable-tftp
tftp-root=%s
dhcp-match=set:pxe-bios,option:client-arch,0
dhcp-boot=tag:pxe-bios,pxelinux.0
`, tftpRoot)
		if _, err := f.WriteString(config); err != nil {
			return "", err
		}
	case "pxe-uefi":
		config := fmt.Sprintf(`enable-tftp
tftp-root=%s
dhcp-match=set:pxe-uefi,option:client-arch,7
dhcp-boot=tag:pxe-uefi,shimx64.efi
`, tftpRoot)
		if _, err := f.WriteString(config); err != nil {
			return "", err
		}
	case "uefi-http":
		config := `dhcp-match=set:efi-x86_64,option:client-arch,16
dhcp-option-force=tag:efi-x86_64,option:vendor-class,HTTPClient
dhcp-boot=tag:efi-x86_64,"http://192.168.128.1:8000/EFI/fedora/shimx64.efi"
`
		if _, err := f.WriteString(config); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unknown mode: %s", mode)
	}

	return f.Name(), nil
}

// startDnsmasq starts dnsmasq with the given config
func startDnsmasq(configFile string) (*exec.Cmd, error) {
	fmt.Println("🌐 Starting dnsmasq")
	cmd := exec.Command("sudo", "dnsmasq", "--interface", "tap0", "-z", "--no-daemon", "-C", configFile, "--log-dhcp", "--log-debug")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start dnsmasq: %w", err)
	}
	// Give dnsmasq time to start
	time.Sleep(2 * time.Second)
	return cmd, nil
}

// startHTTPServer starts a Python HTTP server
func startHTTPServer(workdir string) (*exec.Cmd, error) {
	fmt.Println("🌐 Starting HTTP server on port 8000")
	cmd := exec.Command("python3", "-m", "http.server", "8000", "--bind", "192.168.128.1")
	cmd.Dir = workdir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start HTTP server: %w", err)
	}
	// Give HTTP server time to start
	time.Sleep(2 * time.Second)
	return cmd, nil
}

// startQEMU starts QEMU with appropriate settings
func startQEMU(useUEFI bool) (*exec.Cmd, error) {
	fmt.Println("🖥️  Starting QEMU")
	args := []string{
		"-boot", "menu=on",
		"-netdev", "tap,ifname=tap0,id=net0,script=no",
		"-device", "virtio-net-pci,netdev=net0",
		"-object", "rng-random,id=virtio-rng0,filename=/dev/urandom",
		"-device", "virtio-rng-pci,rng=virtio-rng0,id=rng0,bus=pci.0,addr=0x9",
		"-no-shutdown",
		"-m", "4096",
		"-display", "none",
		"-serial", "mon:stdio",
	}

	if useUEFI {
		args = append(args, "-bios", "/usr/share/edk2/ovmf/OVMF_CODE.fd")
	}

	cmd := exec.Command("qemu-kvm", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start QEMU: %w", err)
	}
	return cmd, nil
}

// waitForSSH waits for SSH to become available on the VM
func waitForSSH(timeout time.Duration) error {
	fmt.Println("⏳ Waiting for VM to boot and SSH to be available")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.Command("nc", "-z", "-w", "1", "192.168.128.100", "22")
		if err := cmd.Run(); err == nil {
			fmt.Println("✅ SSH is available")
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timeout waiting for SSH")
}

// runTestScript executes the test script via SSH
func runTestScript(username, privkey, script, config string) error {
	fmt.Println("🧪 Running test script via SSH")
	cmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-i", privkey,
		fmt.Sprintf("%s@192.168.128.100", username),
		script, config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("test script failed: %w", err)
	}
	fmt.Println("✅ Test script passed")
	return nil
}

// unpackTarball extracts the pxe tarball to a work directory
func unpackTarball(imagePath string) (string, error) {
	fmt.Println("📦 Unpacking PXE tarball")
	workdir, err := os.MkdirTemp("", "pxe-boot-*")
	if err != nil {
		return "", err
	}

	cmd := exec.Command("tar", "xf", imagePath, "-C", workdir)
	if err := cmd.Run(); err != nil {
		os.RemoveAll(workdir)
		return "", fmt.Errorf("failed to unpack tarball: %w", err)
	}

	return workdir, nil
}

// preparePXEBIOS prepares files for PXE BIOS boot
func preparePXEBIOS(workdir string) error {
	fmt.Println("📝 Preparing PXE BIOS files")

	// Install syslinux files
	files := []string{"pxelinux.0", "menu.c32", "libutil.c32"}
	for _, file := range files {
		src := filepath.Join("/usr/share/syslinux", file)
		dst := filepath.Join(workdir, file)
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("failed to copy %s: %w", file, err)
		}
	}

	// Create pxelinux.cfg directory and config
	cfgDir := filepath.Join(workdir, "pxelinux.cfg")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		return err
	}

	config := `default menu.c32
prompt 0
timeout 120

menu title PXE Menu

label fedora
 kernel /vmlinuz
 append initrd=/initrd.img root=live:http://192.168.128.1:8000/rootfs.img rd.live.image
`
	configFile := filepath.Join(cfgDir, "default")
	if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
		return err
	}

	return nil
}

// preparePXEUEFI prepares files for PXE UEFI boot
func preparePXEUEFI(workdir string) error {
	fmt.Println("📝 Preparing PXE UEFI files")

	// Copy grub files from EFI/fedora to root
	efiDir := filepath.Join(workdir, "EFI", "fedora")
	files, err := os.ReadDir(efiDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if !file.IsDir() {
			src := filepath.Join(efiDir, file.Name())
			dst := filepath.Join(workdir, file.Name())
			if err := copyFile(src, dst); err != nil {
				return err
			}
		}
	}

	// Edit grub.cfg to point to HTTP server
	grubCfg := filepath.Join(workdir, "grub.cfg")
	return updateGrubConfig(grubCfg)
}

// prepareUEFIHTTP prepares files for UEFI HTTP boot
func prepareUEFIHTTP(workdir string) error {
	fmt.Println("📝 Preparing UEFI HTTP files")

	// Edit grub.cfg in EFI/fedora to point to HTTP server
	grubCfg := filepath.Join(workdir, "EFI", "fedora", "grub.cfg")
	return updateGrubConfig(grubCfg)
}

// updateGrubConfig updates grub.cfg to use HTTP server
func updateGrubConfig(configPath string) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	// Replace references to use HTTP server
	updated := strings.ReplaceAll(string(content), "root=live:", "root=live:http://192.168.128.1:8000/")
	// Also ensure kernel and initrd paths point to HTTP if not already
	// This is a simple replacement; might need adjustment based on actual grub.cfg format

	if err := os.WriteFile(configPath, []byte(updated), 0644); err != nil {
		return err
	}

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	return destFile.Sync()
}

// runBootMode executes a complete boot test for the specified mode
func runBootMode(mode string, imagePath, username, privkey, pubkey, script, config string) error {
	var err error
	resources := &bootResources{}
	defer resources.cleanup()

	// Unpack tarball
	resources.workdir, err = unpackTarball(imagePath)
	if err != nil {
		return err
	}

	// Setup tap device
	resources.tapDevice = "tap0"
	if err := setupTapDevice(resources.tapDevice); err != nil {
		return err
	}

	// Prepare mode-specific files
	switch mode {
	case "pxe-bios":
		if err := preparePXEBIOS(resources.workdir); err != nil {
			return err
		}
	case "pxe-uefi":
		if err := preparePXEUEFI(resources.workdir); err != nil {
			return err
		}
	case "uefi-http":
		if err := prepareUEFIHTTP(resources.workdir); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}

	// Generate dnsmasq config
	resources.dnsmasqConf, err = generateDnsmasqConfig(mode, resources.workdir)
	if err != nil {
		return err
	}

	// Start dnsmasq
	resources.dnsmasqCmd, err = startDnsmasq(resources.dnsmasqConf)
	if err != nil {
		return err
	}

	// Start HTTP server
	resources.httpCmd, err = startHTTPServer(resources.workdir)
	if err != nil {
		return err
	}

	// Start QEMU
	useUEFI := mode != "pxe-bios"
	resources.qemuCmd, err = startQEMU(useUEFI)
	if err != nil {
		return err
	}

	// Wait for SSH
	if err := waitForSSH(5 * time.Minute); err != nil {
		return err
	}

	// Run test script
	if err := runTestScript(username, privkey, script, config); err != nil {
		return err
	}

	return nil
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "boot-pxe",
		Short: "Boot and test PXE images",
	}

	// Common flags
	var (
		imagePath string
		username  string
		privkey   string
		pubkey    string
		script    string
		config    string
	)

	// pxe-bios command
	pxeBiosCmd := &cobra.Command{
		Use:   "pxe-bios",
		Short: "Boot via PXE BIOS",
		Run: func(cmd *cobra.Command, args []string) {
			err := runBootMode("pxe-bios", imagePath, username, privkey, pubkey, script, config)
			exitCheck(err)
		},
	}

	// pxe-uefi command
	pxeUefiCmd := &cobra.Command{
		Use:   "pxe-uefi",
		Short: "Boot via PXE UEFI",
		Run: func(cmd *cobra.Command, args []string) {
			err := runBootMode("pxe-uefi", imagePath, username, privkey, pubkey, script, config)
			exitCheck(err)
		},
	}

	// uefi-http command
	uefiHttpCmd := &cobra.Command{
		Use:   "uefi-http",
		Short: "Boot via UEFI HTTP",
		Run: func(cmd *cobra.Command, args []string) {
			err := runBootMode("uefi-http", imagePath, username, privkey, pubkey, script, config)
			exitCheck(err)
		},
	}

	// Add flags to all subcommands
	for _, cmd := range []*cobra.Command{pxeBiosCmd, pxeUefiCmd, uefiHttpCmd} {
		cmd.Flags().StringVar(&imagePath, "image-path", "", "Path to PXE tarball")
		cmd.Flags().StringVar(&username, "username", "osbuild", "SSH username")
		cmd.Flags().StringVar(&privkey, "ssh-privkey", "", "Path to SSH private key")
		cmd.Flags().StringVar(&pubkey, "ssh-pubkey", "", "Path to SSH public key")
		cmd.Flags().StringVar(&script, "script", "", "Test script to run")
		cmd.Flags().StringVar(&config, "config", "", "Config file path")
		cmd.MarkFlagRequired("image-path")
		cmd.MarkFlagRequired("ssh-privkey")
		cmd.MarkFlagRequired("script")
		cmd.MarkFlagRequired("config")
	}

	rootCmd.AddCommand(pxeBiosCmd, pxeUefiCmd, uefiHttpCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
