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
