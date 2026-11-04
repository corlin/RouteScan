package geoip

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	// OpenMMDBURL 开源精简版全球 IP/ASN mmdb 镜像源
	OpenMMDBURL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"
)

// DefaultDBPath 返回默认的本地 GeoIP 数据库存储路径 (~/.routescan/geoip.mmdb)
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".routescan", "geoip.mmdb")
}

// DownloadDatabase 下载远端 MMDB 镜像到临时文件，下载完成后原子重命名至 destPath
func DownloadDatabase(destPath string) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpFile := destPath + ".tmp"
	client := &http.Client{Timeout: 60 * time.Second}

	resp, err := client.Get(OpenMMDBURL)
	if err != nil {
		return fmt.Errorf("下载 MMDB 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 MMDB 失败，HTTP 状态码: %d", resp.StatusCode)
	}

	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
		_ = os.Remove(tmpFile)
	}()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}

	if err := out.Close(); err != nil {
		return err
	}

	return os.Rename(tmpFile, destPath)
}

// EnsureDatabase 确保数据库已加载。若文件已存在则直接加载；若不存在且 autoDownload 为 true，则在后台协程异步下载并热重载。
func EnsureDatabase(mgr *Manager, autoDownload bool) {
	if mgr == nil {
		return
	}

	mgr.mu.RLock()
	targetPath := mgr.dbPath
	mgr.mu.RUnlock()

	if targetPath == "" {
		targetPath = DefaultDBPath()
	}

	if _, err := os.Stat(targetPath); err == nil {
		_ = mgr.LoadDB(targetPath)
		return
	}

	if autoDownload {
		go func() {
			if err := DownloadDatabase(targetPath); err == nil {
				_ = mgr.LoadDB(targetPath)
			}
		}()
	}
}
