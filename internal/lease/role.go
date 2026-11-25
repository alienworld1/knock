package lease

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func Role(role, id, command string, input io.Reader, output io.Writer) error {
	if !validID(id) || (role != "logs" && role != "maintenance") || os.Geteuid() == 0 {
		return errors.New("invalid diagnostic role")
	}
	if command != "" {
		return roleCommand(role, id, command, output)
	}
	menu := "Commands: status, quit"
	if role == "maintenance" {
		menu = "Commands: status, start, quit"
	}
	fmt.Fprintln(output, menu)
	in := bufio.NewScanner(input)
	in.Buffer(make([]byte, 256), 256)
	for in.Scan() {
		command = strings.TrimSpace(in.Text())
		if command == "quit" {
			return nil
		}
		if err := roleCommand(role, id, command, output); err != nil {
			fmt.Fprintln(output, err)
		}
	}
	return in.Err()
}

func roleCommand(role, id, command string, output io.Writer) error {
	switch command {
	case "status":
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return errors.New("couldn't read host uptime")
		}
		var uptime float64
		if _, err := fmt.Sscanf(string(data), "%f", &uptime); err != nil {
			return errors.New("couldn't read host uptime")
		}
		fmt.Fprintf(output, "Host uptime: %.0fs\n", uptime)
	case "start":
		if role != "maintenance" {
			return errors.New("command unavailable for this role")
		}
		file, err := os.Open(filepath.Join(public, id))
		if err != nil {
			return errors.New("couldn't start the diagnostic workload")
		}
		defer file.Close()
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return errors.New("a diagnostic workload is already running")
		}
		cmd := exec.Command(daemonPath, "ssh-workload")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.ExtraFiles = []*os.File{file}
		out, err := cmd.Output()
		if err != nil {
			return errors.New("couldn't start the diagnostic workload")
		}
		fmt.Fprintf(output, "Workload %s", out)
	default:
		return errors.New("command unavailable for this role")
	}
	return nil
}

// LaunchWorkload starts a fixed diagnostic process and hands off the lock to it.
// Both forks remain in the systemd service's cgroup even after SSH disconnects.
func LaunchWorkload() error {
	if os.Geteuid() == 0 {
		return errors.New("invalid diagnostic user")
	}
	lock := os.NewFile(3, "workload lock")
	defer lock.Close()
	if _, err := lock.Stat(); err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/sleep", "86400")
	cmd.ExtraFiles = []*os.File{lock}
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Println(cmd.Process.Pid)
	return cmd.Process.Release()
}
