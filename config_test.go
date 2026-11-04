package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "netlight.json")
	os.WriteFile(p, []byte(`{
	  "org": "範例公司",
	  "contact": {"default": "IT 分機 1234"},
	  "targets": [{"name": "公司 ERP", "url": "https://erp.example.com"}]
	}`), 0o644)

	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Org != "範例公司" || cfg.contactFor(DNSCode) != "IT 分機 1234" {
		t.Errorf("設定內容不符：%+v", cfg)
	}
	ts := cfg.targets()
	if len(ts) != len(defaultTargets)+1 || ts[len(ts)-1].Name != "公司 ERP" {
		t.Errorf("目標應為預設 + 自訂：%+v", ts)
	}

	cfg.ReplaceDefaultTargets = true
	if ts := cfg.targets(); len(ts) != 1 {
		t.Errorf("replace_default_targets 應只留自訂目標：%+v", ts)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"targets": [{"name": "x", "url": "ftp://x"}]}`), 0o644)
	if _, err := loadConfig(bad); err == nil {
		t.Error("非 https 網址應回報錯誤")
	}
	broken := filepath.Join(dir, "broken.json")
	os.WriteFile(broken, []byte(`{`), 0o644)
	if _, err := loadConfig(broken); err == nil {
		t.Error("格式錯誤的 JSON 應回報錯誤")
	}
	if _, err := loadConfig(filepath.Join(dir, "none.json")); err == nil {
		t.Error("不存在的檔案應回報錯誤")
	}
	trailingObj := filepath.Join(dir, "trailing_obj.json")
	os.WriteFile(trailingObj, []byte(`{"org":"x"} {"org":"y"}`), 0o644)
	if _, err := loadConfig(trailingObj); err == nil || !strings.Contains(err.Error(), "多餘內容") {
		t.Errorf("JSON 結尾有多餘物件應報「多餘內容」，得到 %v", err)
	}
	trailingJunk := filepath.Join(dir, "trailing_junk.json")
	os.WriteFile(trailingJunk, []byte(`{"org":"x"} junk`), 0o644)
	if _, err := loadConfig(trailingJunk); err == nil || !strings.Contains(err.Error(), "多餘內容") {
		t.Errorf("JSON 結尾有多餘文字應報「多餘內容」，得到 %v", err)
	}
	trailingSpace := filepath.Join(dir, "trailing_space.json")
	os.WriteFile(trailingSpace, []byte("{\"org\":\"x\"}\n\n\t"), 0o644)
	if _, err := loadConfig(trailingSpace); err != nil {
		t.Errorf("結尾只有空白的設定檔應可載入：%v", err)
	}
}

func TestFindConfig(t *testing.T) {
	dir := t.TempDir()
	if got := findConfig(dir, dir); got != "" {
		t.Errorf("沒有設定檔時應回空字串，得到 %q", got)
	}
	p := filepath.Join(dir, "netlight.json")
	os.WriteFile(p, []byte(`{}`), 0o644)
	if got := findConfig(t.TempDir(), dir); got != p {
		t.Errorf("應在目前目錄找到 %q，得到 %q", p, got)
	}
	if got := findConfig(dir, t.TempDir()); got != p {
		t.Errorf("應在執行檔目錄找到 %q，得到 %q", p, got)
	}
}

func TestLoadConfigStrict(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(dir, "netlight.json")
		os.WriteFile(p, []byte(content), 0o644)
		return p
	}
	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{"未知欄位", `{"targetz": []}`, ""},
		{"不認得的結論碼", `{"contact": {"dsn": "x"}}`, "dsn"},
		{"重複的結論碼", `{"contact": {"dns": "a", "DNS": "b"}}`, ""},
		{"空 targets", `{"replace_default_targets": true}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := loadConfig(write(c.content)); err == nil {
				t.Errorf("%s 應回報錯誤", c.name)
			} else if c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("錯誤訊息應含 %q，得到 %v", c.wantErr, err)
			}
		})
	}

	// contact key 大小寫不拘
	cfg, err := loadConfig(write(`{"contact": {"DNS": "x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.contactFor(DNSCode); got != "x" {
		t.Errorf("大寫 key 應可使用，contactFor(DNS) = %q", got)
	}
}

func TestLoadConfigExample(t *testing.T) {
	if _, err := loadConfig("netlight.example.json"); err != nil {
		t.Errorf("netlight.example.json 應可成功載入：%v", err)
	}
}

func TestContactForProxyPAC(t *testing.T) {
	cfg := Config{Contact: map[string]string{"proxy": "網管組", "default": "總機"}}
	if got := cfg.contactFor(ProxyPACCode); got != "網管組" {
		t.Errorf("只有 proxy 時應改用 proxy，得到 %q", got)
	}
	cfg = Config{Contact: map[string]string{"default": "總機"}}
	if got := cfg.contactFor(ProxyPACCode); got != "總機" {
		t.Errorf("只有 default 時應用 default，得到 %q", got)
	}
}

func TestPublicIPEnabled(t *testing.T) {
	// 缺省 → true
	cfg := Config{}
	if !cfg.publicIPEnabled() {
		t.Error("缺省 show_public_ip 應為 true")
	}
	// 明確 false → false
	f := false
	cfg = Config{ShowPublicIP: &f}
	if cfg.publicIPEnabled() {
		t.Error("show_public_ip 設 false 應為 false")
	}
	// 明確 true → true
	tr := true
	cfg = Config{ShowPublicIP: &tr}
	if !cfg.publicIPEnabled() {
		t.Error("show_public_ip 設 true 應為 true")
	}
	// netlight.example.json（已含 show_public_ip）仍可載入
	if _, err := loadConfig("netlight.example.json"); err != nil {
		t.Errorf("netlight.example.json 應可成功載入：%v", err)
	}
}

func TestLoadConfigCheckpoints(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(dir, "netlight.json")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// 合法檢查點：ping、dns、tcp:<埠> 都可載入
	p := write(`{"checkpoints": [
		{"name": "單位防火牆", "host": "10.1.0.1", "check": "tcp:443"},
		{"name": "GSN DNS", "host": "210.69.1.1", "check": "dns"},
		{"name": "內網主機", "host": "host.corp.example", "check": "ping"}
	]}`)
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatalf("合法檢查點應可載入：%v", err)
	}
	if len(cfg.Checkpoints) != 3 || cfg.Checkpoints[0].Host != "10.1.0.1" {
		t.Errorf("檢查點內容不符：%+v", cfg.Checkpoints)
	}

	bad := []struct {
		name    string
		content string
	}{
		{"不支援的檢查方式", `{"checkpoints": [{"name": "x", "host": "10.1.0.1", "check": "udp:53"}]}`},
		{"埠號為 0", `{"checkpoints": [{"name": "x", "host": "10.1.0.1", "check": "tcp:0"}]}`},
		{"埠號超過 65535", `{"checkpoints": [{"name": "x", "host": "10.1.0.1", "check": "tcp:70000"}]}`},
		{"name 是空白", `{"checkpoints": [{"name": "  ", "host": "10.1.0.1", "check": "ping"}]}`},
		{"host 含空白", `{"checkpoints": [{"name": "x", "host": "10.1 0.1", "check": "ping"}]}`},
		{"host 結尾有 tab", "{\"checkpoints\": [{\"name\": \"x\", \"host\": \"10.1.0.1\\t\", \"check\": \"ping\"}]}"},
		{"host 結尾有全形空白", "{\"checkpoints\": [{\"name\": \"x\", \"host\": \"10.1.0.1　\", \"check\": \"ping\"}]}"},
		{"超過 10 個", `{"checkpoints": [
			{"name": "1", "host": "10.1.0.1", "check": "ping"},
			{"name": "2", "host": "10.1.0.2", "check": "ping"},
			{"name": "3", "host": "10.1.0.3", "check": "ping"},
			{"name": "4", "host": "10.1.0.4", "check": "ping"},
			{"name": "5", "host": "10.1.0.5", "check": "ping"},
			{"name": "6", "host": "10.1.0.6", "check": "ping"},
			{"name": "7", "host": "10.1.0.7", "check": "ping"},
			{"name": "8", "host": "10.1.0.8", "check": "ping"},
			{"name": "9", "host": "10.1.0.9", "check": "ping"},
			{"name": "10", "host": "10.1.0.10", "check": "ping"},
			{"name": "11", "host": "10.1.0.11", "check": "ping"}
		]}`},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := loadConfig(write(c.content)); err == nil {
				t.Errorf("%s 應回報錯誤", c.name)
			}
		})
	}

	// org_network 可作為 contact key
	p = write(`{"contact": {"org_network": "單位資訊室 分機 2211"}}`)
	if _, err := loadConfig(p); err != nil {
		t.Errorf("org_network 應可作為 contact key：%v", err)
	}
}

func TestLoadConfigCheckpointRequired(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(dir, "netlight.json")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// required: false → 參考節點
	cfg, err := loadConfig(write(`{"checkpoints": [
		{"name": "內部入口網", "host": "10.1.0.2", "check": "tcp:443", "required": false}
	]}`))
	if err != nil {
		t.Fatalf("required: false 應可載入：%v", err)
	}
	if len(cfg.Checkpoints) != 1 || cfg.Checkpoints[0].required() {
		t.Errorf("required: false 應為參考節點：%+v", cfg.Checkpoints)
	}

	// 省略 required → 必要節點
	cfg, err = loadConfig(write(`{"checkpoints": [
		{"name": "單位防火牆", "host": "10.1.0.1", "check": "tcp:443"}
	]}`))
	if err != nil {
		t.Fatalf("省略 required 應可載入：%v", err)
	}
	if len(cfg.Checkpoints) != 1 || !cfg.Checkpoints[0].required() {
		t.Errorf("省略 required 應為必要節點：%+v", cfg.Checkpoints)
	}

	// required: true → 必要節點
	cfg, err = loadConfig(write(`{"checkpoints": [
		{"name": "單位防火牆", "host": "10.1.0.1", "check": "tcp:443", "required": true}
	]}`))
	if err != nil {
		t.Fatalf("required: true 應可載入：%v", err)
	}
	if len(cfg.Checkpoints) != 1 || !cfg.Checkpoints[0].required() {
		t.Errorf("required: true 應為必要節點：%+v", cfg.Checkpoints)
	}

	// required 不是布林值 → 設定檔錯誤
	if _, err := loadConfig(write(`{"checkpoints": [
		{"name": "x", "host": "10.1.0.1", "check": "ping", "required": "no"}
	]}`)); err == nil {
		t.Error("required 為字串應回報錯誤")
	}
}
