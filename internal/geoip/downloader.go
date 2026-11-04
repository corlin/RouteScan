package geoip

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

var (
	// OpenMMDBURL 开源轻量精简版全球 IP mmdb 镜像源 (约 3.2MB，下载极速且全球高精度)
	OpenMMDBURL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"
)

// DefaultDBPath 返回默认的本地 GeoIP 数据库存储路径 (~/.routescan/geoip.mmdb)
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".routescan", "geoip.mmdb")
}

// DownloadDatabase 下载远端 MMDB 镜像到临时文件，下载完成后原子重命名至 destPath。支持传入可选的 proxyURL。
func DownloadDatabase(destPath string, proxyURLs ...string) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	proxyURL := ""
	if len(proxyURLs) > 0 {
		proxyURL = proxyURLs[0]
	}

	tmpFile := destPath + ".tmp"
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   180 * time.Second,
	}

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
func EnsureDatabase(mgr *Manager, autoDownload bool, proxyURLs ...string) {
	if mgr == nil {
		return
	}

	proxyURL := ""
	if len(proxyURLs) > 0 {
		proxyURL = proxyURLs[0]
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
			if err := DownloadDatabase(targetPath, proxyURL); err == nil {
				_ = mgr.LoadDB(targetPath)
			}
		}()
	}
}
