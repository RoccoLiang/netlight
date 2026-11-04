package main

import (
	"bytes"
	"strings"
	"testing"
)

// mapGoldenCase：產生 Report 供 renderMap golden 測試
func mapGoldenCase(name string) Report {
	mk := screens()[name]
	f, cfg := mk()
	return decide(f, cfg)
}

func TestRenderMapGolden(t *testing.T) {
	for _, name := range []string{"map_b_dns", "map_c_router", "map_o_org_down"} {
		r := mapGoldenCase(strings.TrimPrefix(name, "map_"))
		var b bytes.Buffer
		renderMap(&b, r.Lights, false)
		checkGolden(t, name, b.Bytes())

		lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
		brokenIdx := -1
		brokenCount := 0
		for i, ln := range lines {
			if strings.Contains(ln, "◀ 斷在這裡") {
				brokenCount++
				brokenIdx = i
			}
		}
		if brokenCount != 1 {
			t.Errorf("%s 應恰有一行含「◀ 斷在這裡」，實際 %d 行", name, brokenCount)
			continue
		}
		// 該行必須是第一個 Red 的站：之前的站行符號不是 ╳
		for _, ln := range lines[:brokenIdx] {
			if strings.Contains(ln, "╳ ") {
				t.Errorf("%s 「◀ 斷在這裡」不在第一個 Red 的站：\n%s", name, b.String())
				break
			}
		}
		// 斷點之後的連接線為 ┆、之前為 │
		for i, ln := range lines {
			switch ln {
			case "  ┆":
				if i < brokenIdx {
					t.Errorf("%s 斷點之前不應出現 ┆：\n%s", name, b.String())
				}
			case "  │":
				if i > brokenIdx {
					t.Errorf("%s 斷點之後不應出現 │：\n%s", name, b.String())
				}
			}
		}
	}
}

func TestRenderMapAllGreen(t *testing.T) {
	r := mapGoldenCase("a_ok")
	var b bytes.Buffer
	renderMap(&b, r.Lights, false)
	if strings.Contains(b.String(), "◀ 斷在這裡") || strings.Contains(b.String(), "┆") {
		t.Errorf("全部正常時不應有斷點標記或虛線：\n%s", b.String())
	}
}

func TestRenderMapDetail(t *testing.T) {
	r := mapGoldenCase("a_ok")
	var b bytes.Buffer
	renderMap(&b, r.Lights, true)
	if !strings.Contains(b.String(), "  │     · ") {
		t.Errorf("detail 模式應列出證據：\n%s", b.String())
	}
	if !strings.Contains(b.String(), "        · ") {
		t.Errorf("detail 模式最後一站證據應以空白縮排：\n%s", b.String())
	}
}

func TestMapFrame(t *testing.T) {
	names := []string{"本機網路", "路由器", "對外連線"}
	lines := mapFrame(names, []mapState{statePending, stateDone, statePending}, 1)
	if len(lines) != 5 {
		t.Fatalf("行數 = %d，預期 5（3 站＋2 連接線）", len(lines))
	}
	if !strings.Contains(lines[0], "◓ 檢查中") || !strings.Contains(lines[4], "◓ 檢查中") {
		t.Errorf("第 1、3 站應含「◓ 檢查中」：%q / %q", lines[0], lines[4])
	}
	if !strings.Contains(lines[2], "已完成，判斷中") {
		t.Errorf("第 2 站應含「已完成，判斷中」：%q", lines[2])
	}
	if lines[1] != "  │" || lines[3] != "  │" {
		t.Errorf("連接線應為「  │」：%q / %q", lines[1], lines[3])
	}
}

func TestMapStates(t *testing.T) {
	names := lightNames(Config{})
	states := mapStates(names, map[string]bool{"dns": true})
	if states[3] != statePending {
		t.Errorf("done 只有 dns 時「網址查詢」應為等待中")
	}
	states = mapStates(names, map[string]bool{"dns": true, "public_dns": true})
	if states[3] != stateDone {
		t.Errorf("dns、public_dns 都有時「網址查詢」應為已完成")
	}
	for _, s := range mapStates(names, map[string]bool{}) {
		if s != statePending {
			t.Errorf("空的 done 全部應為等待中")
		}
	}
}

func TestLightNeedsCoversNames(t *testing.T) {
	cfg := Config{Checkpoints: []Checkpoint{{Host: "10.1.0.1", Check: "tcp:443"}}}
	for _, name := range lightNames(cfg) {
		if _, ok := lightNeeds[name]; !ok {
			t.Errorf("lightNeeds 缺少站名 %q", name)
		}
	}
}
