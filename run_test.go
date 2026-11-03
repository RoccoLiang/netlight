package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProxyFunc(t *testing.T) {
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	req, _ := http.NewRequest("GET", "https://www.google.com", nil)
	if proxyFunc(Proxy{}) != nil || proxyFunc(Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}) != nil {
		t.Error("無代理與 PAC 應直連")
	}
	erp, _ := http.NewRequest("GET", "https://erp.corp.example", nil)
	// 明確代理加 Bypass：符合者直連、其餘走代理
	f := proxyFunc(Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128", Bypass: []string{"*.corp.example"}})
	if u, err := f(erp); u != nil || err != nil {
		t.Errorf("符合例外應直連，得到 %v, %v", u, err)
	}
	if u, err := f(req); err != nil || u == nil || u.Host != "10.0.0.8:3128" {
		t.Errorf("不符合例外應走代理，得到 %v, %v", u, err)
	}
	u, err := proxyFunc(Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"})(req)
	if err != nil || u.Host != "10.0.0.8:3128" {
		t.Errorf("明確代理 = %v, %v", u, err)
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7999")
	if u, _ := proxyFunc(Proxy{Mode: ProxyEnv})(req); u == nil || u.Host != "127.0.0.1:7999" {
		t.Errorf("環境變數代理 = %v", u)
	}
	// ProxyEnv 對 NO_PROXY 例外直連
	t.Setenv("NO_PROXY", "*.corp.example")
	if u, _ := proxyFunc(Proxy{Mode: ProxyEnv})(erp); u != nil {
		t.Errorf("環境變數代理的例外應直連，得到 %v", u)
	}
	t.Setenv("NO_PROXY", "")
	// 依 scheme 選 HTTP_PROXY／HTTPS_PROXY；localhost 與 loopback 直連
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:7001")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7002")
	envf := proxyFunc(Proxy{Mode: ProxyEnv})
	if u, _ := envf(mustReq(t, "http://example.com")); u == nil || u.Host != "127.0.0.1:7001" {
		t.Errorf("http 應走 HTTP_PROXY，得到 %v", u)
	}
	if u, _ := envf(mustReq(t, "https://example.com")); u == nil || u.Host != "127.0.0.1:7002" {
		t.Errorf("https 應走 HTTPS_PROXY，得到 %v", u)
	}
	if u, _ := envf(mustReq(t, "https://localhost/")); u != nil {
		t.Errorf("https://localhost 應直連，得到 %v", u)
	}
	if u, _ := envf(mustReq(t, "http://127.0.0.1/")); u != nil {
		t.Errorf("http://127.0.0.1 應直連，得到 %v", u)
	}
	// newClient 只設 HTTP_PROXY 時：http 走代理、https 直連
	t.Setenv("HTTPS_PROXY", "")
	tr := newClient(Proxy{Mode: ProxyEnv}, nil, time.Second).Transport.(*http.Transport)
	if u, err := tr.Proxy(mustReq(t, "http://example.com")); err != nil || u == nil || u.Host != "127.0.0.1:7001" {
		t.Errorf("newClient 對 http 應走 HTTP_PROXY，得到 %v, %v", u, err)
	}
	if u, err := tr.Proxy(mustReq(t, "https://example.com")); err != nil || u != nil {
		t.Errorf("newClient 對 https 且無 HTTPS_PROXY 應直連，得到 %v, %v", u, err)
	}
}

func mustReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// 實機整合測試：不檢查結論（取決於當下網路），只檢查流程完整、在預算內結束
func TestRunIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 時略過實機網路測試")
	}
	start := time.Now()
	f := run(context.Background(), Config{})
	if el := time.Since(start); el > totalBudget+time.Second {
		t.Errorf("執行 %s，超過預算 %s", el, totalBudget)
	}
	if f.Local.OS == "" {
		t.Error("應填入作業系統名稱")
	}
	r := decide(f, Config{})
	t.Logf("結論：%s；本機：%+v", r.Verdict.Code, f.Local)
	if f.NoLink {
		t.Skip("目前沒有網路，略過探測數量檢查")
	}
	if len(f.Sites) != len(defaultTargets) || len(f.Direct) != len(directTargets) || len(f.DNS) != len(defaultTargets) {
		t.Errorf("探測數量不符：%d sites, %d direct, %d dns", len(f.Sites), len(f.Direct), len(f.DNS))
	}
	for i, p := range f.PublicDNS {
		if want := strings.TrimSuffix(publicDNS[i], ":53"); p.Target != want {
			t.Errorf("PublicDNS[%d].Target = %q，預期 %q", i, p.Target, want)
		}
	}
	for _, tr := range f.PublicIP {
		t.Logf("對外 IP：%s %s（%s）", tr.Name, tr.IP, tr.Loc)
	}
}

// 實機測試：收集 emit 的 stage，各組探測完成時應各出現一次
func TestRunWithEventsStages(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 時略過實機網路測試")
	}
	var stages []string
	f := runWithEvents(context.Background(), Config{}, func(stage string) { stages = append(stages, stage) })
	counts := map[string]int{}
	for _, s := range stages {
		counts[s]++
	}
	if counts[stageLocal] != 1 {
		t.Errorf("local 應出現一次，實際 %d 次", counts[stageLocal])
	}
	if f.NoLink {
		return
	}
	for _, s := range []string{stageDirect, stagePublicDNS, stageDNS, stageSites, stageCaptive} {
		if counts[s] != 1 {
			t.Errorf("%s 應出現一次，實際 %d 次（全部：%v）", s, counts[s], stages)
		}
	}
	if counts[stageGateway] > 1 {
		t.Errorf("gateway 最多出現一次，實際 %d 次", counts[stageGateway])
	}
}
