package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

const configName = "netlight.json"

type Target struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Checkpoint struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Check    string `json:"check"`    // "ping"、"dns"、"tcp:<port>"
	Required *bool  `json:"required"` // 省略時視為必要節點
}

// required：此檢查點是否為必要節點（未標註時預設 true）
func (c Checkpoint) required() bool { return c.Required == nil || *c.Required }

// Config：放在執行檔旁的 netlight.json，用來改成公司窗口與加入內部網站
type Config struct {
	Org                   string            `json:"org"`
	Contact               map[string]string `json:"contact"` // key 為小寫結論碼（如 dns、isp）或 default
	Targets               []Target          `json:"targets"`
	ReplaceDefaultTargets bool              `json:"replace_default_targets"`
	ShowPublicIP          *bool             `json:"show_public_ip"`
	Checkpoints           []Checkpoint      `json:"checkpoints"`
}

// checkpointDNSPort：檢查點 DNS 查詢使用的埠（測試可替換成本機假伺服器）
var checkpointDNSPort = "53"

// validateCheckpoints：驗證 checkpoints 欄位（第幾個從 1 起算）
func validateCheckpoints(cps []Checkpoint) error {
	if len(cps) > 10 {
		return fmt.Errorf("設定檔 checkpoints 最多 10 個（目前 %d 個）", len(cps))
	}
	for i, cp := range cps {
		n := i + 1
		if strings.TrimSpace(cp.Name) == "" {
			return fmt.Errorf("設定檔第 %d 個檢查點的 name 不可為空", n)
		}
		if cp.Host == "" || strings.ContainsRune(cp.Host, '/') || strings.ContainsFunc(cp.Host, unicode.IsSpace) {
			return fmt.Errorf("設定檔第 %d 個檢查點的 host 必須是 IP 或主機名稱（不可含空白或斜線）", n)
		}
		switch {
		case cp.Check == "ping":
			if strings.Contains(cp.Host, ":") {
				return fmt.Errorf("設定檔第 %d 個檢查點的 check 為 ping 時，host 不可使用 IPv6 位址", n)
			}
		case cp.Check == "dns":
		case strings.HasPrefix(cp.Check, "tcp:"):
			p, err := strconv.Atoi(strings.TrimPrefix(cp.Check, "tcp:"))
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("設定檔第 %d 個檢查點的 check 埠號必須在 1～65535", n)
			}
		default:
			return fmt.Errorf("設定檔第 %d 個檢查點的 check 必須是 ping、dns 或 tcp:<埠>", n)
		}
	}
	return nil
}

// publicIPEnabled：是否查詢對外 IP（預設 true）
func (c Config) publicIPEnabled() bool { return c.ShowPublicIP == nil || *c.ShowPublicIP }

// 預設目標：三家不同的服務商 + 一個台灣網站
var defaultTargets = []Target{
	{"Google", "https://www.google.com"},
	{"Cloudflare", "https://www.cloudflare.com"},
	{"Microsoft", "https://www.microsoft.com"},
	{"政府入口網", "https://www.gov.tw"},
}

func (c Config) targets() []Target {
	if c.ReplaceDefaultTargets {
		return c.Targets
	}
	return slices.Concat(defaultTargets, c.Targets)
}

// validContactKeys：contact 可用的 key（default 與全部結論碼的小寫）
var validContactKeys = func() map[string]bool {
	m := map[string]bool{"default": true}
	for _, c := range []Code{OK, NoLink, NoDHCP, Portal, Clock, VPNBroken, ProxyCode, ProxyPACCode, ISP, RouterOrISP, OrgNetwork, DNSCode, TLSIntercept, Filtered, SiteCode, Unstable, Unknown} {
		m[strings.ToLower(string(c))] = true
	}
	return m
}()

func (c Config) contactFor(code Code) string {
	if s := c.Contact[strings.ToLower(string(code))]; s != "" {
		return s
	}
	if code == ProxyPACCode {
		if s := c.Contact["proxy"]; s != "" {
			return s
		}
	}
	return c.Contact["default"]
}

func loadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("讀取設定檔失敗：%w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("設定檔 %s 格式錯誤：%w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return c, fmt.Errorf("設定檔 %s 格式錯誤：JSON 結尾有多餘內容", path)
	}
	normalized := make(map[string]string, len(c.Contact))
	for k, v := range c.Contact {
		lk := strings.ToLower(k)
		if !validContactKeys[lk] {
			return c, fmt.Errorf("設定檔 contact 有不認得的結論碼「%s」", k)
		}
		if _, dup := normalized[lk]; dup {
			return c, fmt.Errorf("設定檔 contact 有重複的結論碼：%s", k)
		}
		normalized[lk] = v
	}
	c.Contact = normalized
	if c.ReplaceDefaultTargets && len(c.Targets) == 0 {
		return c, fmt.Errorf("設定檔把 replace_default_targets 設為 true，但 targets 是空的")
	}
	for _, t := range c.Targets {
		u, err := url.Parse(t.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return c, fmt.Errorf("設定檔目標「%s」的網址必須是 https://：%s", t.Name, t.URL)
		}
	}
	if err := validateCheckpoints(c.Checkpoints); err != nil {
		return c, err
	}
	return c, nil
}

// findConfig：先找執行檔所在目錄，再找目前目錄
func findConfig(exeDir, cwd string) string {
	for _, d := range []string{exeDir, cwd} {
		p := filepath.Join(d, configName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
