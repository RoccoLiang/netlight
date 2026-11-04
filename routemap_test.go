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

// splitMapLines：切出輸出行（去除結尾換行）
func splitMapLines(t *testing.T, out string) []string {
	t.Helper()
	return strings.Split(strings.TrimSuffix(out, "\n"), "\n")
}

// firstRedLight：第一個 Red 燈的索引；沒有 Red 回 -1
func firstRedLight(lights []Light) int {
	for i, l := range lights {
		if l.Status == Red {
			return i
		}
	}
	return -1
}

func TestRenderMapGolden(t *testing.T) {
	for _, name := range []string{"map_b_dns", "map_c_router", "map_o_org_down"} {
		r := mapGoldenCase(strings.TrimPrefix(name, "map_"))
		var b bytes.Buffer
		renderMap(&b, r.Lights, false)
		checkGolden(t, name, b.Bytes())

		lines := splitMapLines(t, b.String())
		brokenIdx := firstRedLight(r.Lights)
		if brokenIdx < 0 {
			t.Fatalf("%s 應有 Red 燈", name)
		}

		// 恰有一行含「◀ 斷在這裡」，且同時含第一個 Red 燈的名稱
		brokenLines := 0
		for _, ln := range lines {
			if strings.Contains(ln, "◀ 斷在這裡") {
				brokenLines++
				if !strings.Contains(ln, r.Lights[brokenIdx].Name) {
					t.Errorf("%s 「◀ 斷在這裡」行不含第一個 Red 燈名稱 %q：%q", name, r.Lights[brokenIdx].Name, ln)
				}
			}
		}
		if brokenLines != 1 {
			t.Errorf("%s 應恰有一行含「◀ 斷在這裡」，實際 %d 行", name, brokenLines)
		}

		// 連接線總數 = 燈數 - 1；斷點之後全為 ┆、之前全為 │
		connCount := 0
		for _, ln := range lines {
			if ln == "  │" || ln == "  ┆" {
				connCount++
			}
		}
		if connCount != len(r.Lights)-1 {
			t.Errorf("%s 連接線總數 = %d，預期 %d", name, connCount, len(r.Lights)-1)
		}
		connIdx := 0 // 目前是第幾條連接線（在站 brokenIdx 之後的連接線應為 ┆）
		for _, ln := range lines {
			if ln != "  │" && ln != "  ┆" {
				continue
			}
			if connIdx >= brokenIdx {
				if ln != "  ┆" {
					t.Errorf("%s 第 %d 條連接線應為 ┆：%q", name, connIdx, ln)
				}
			} else if ln != "  │" {
				t.Errorf("%s 第 %d 條連接線應為 │：%q", name, connIdx, ln)
			}
			connIdx++
		}
	}
}

func TestRenderMapAllGreen(t *testing.T) {
	r := mapGoldenCase("a_ok")
	var b bytes.Buffer
	renderMap(&b, r.Lights, false)
	out := b.String()
	if strings.Contains(out, "◀ 斷在這裡") || strings.Contains(out, "┆") {
		t.Errorf("全部正常時不應有斷點標記或虛線：\n%s", out)
	}
	lines := splitMapLines(t, out)
	if len(lines) != 2*len(r.Lights)-1 {
		t.Errorf("行數 = %d，預期 %d", len(lines), 2*len(r.Lights)-1)
	}
	var order []int
	for i, ln := range lines {
		if i%2 == 0 { // 站行
			for j, l := range r.Lights {
				if strings.Contains(ln, l.Name) {
					order = append(order, j)
					break
				}
			}
		} else if ln != "  │" {
			t.Errorf("第 %d 行應為連接線：%q", i, ln)
		}
	}
	// 每個燈名都出現且依序
	for i, want := range order {
		if i != want {
			t.Fatalf("站順序 = %v，預期依序出現", order)
		}
	}
	if len(order) != len(r.Lights) {
		t.Errorf("站行數 = %d，預期 %d", len(order), len(r.Lights))
	}
}

func TestRenderMapDetail(t *testing.T) {
	lights := []Light{
		{Name: "本機網路", Status: Green, Summary: "Wi-Fi 192.168.1.23", Evidence: []string{"介面：en0", "IP：192.168.1.23"}},
		{Name: "路由器", Status: Red, Summary: "192.168.1.1 沒有回應", Evidence: []string{"路由器位址：192.168.1.1"}},
		{Name: "對外連線", Status: Skip, Summary: "前一段異常，未檢查", Evidence: []string{"未檢查"}},
	}
	var b bytes.Buffer
	renderMap(&b, lights, true)
	want := "  ● 本機網路　🟢 正常  Wi-Fi 192.168.1.23\n" +
		"  │     · 介面：en0\n" +
		"  │     · IP：192.168.1.23\n" +
		"  │\n" +
		"  ╳ 路由器　　🔴 故障  192.168.1.1 沒有回應  ◀ 斷在這裡\n" +
		"  │     · 路由器位址：192.168.1.1\n" +
		"  ┆\n" +
		"  ○ 對外連線　⚪ 略過  前一段異常，未檢查\n" +
		"        · 未檢查\n"
	if b.String() != want {
		t.Errorf("detail 輸出不符：\n--- 得到 ---\n%s\n--- 預期 ---\n%s", b.String(), want)
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
	names := lightNames(cfg)
	if len(lightNeeds) != len(names) {
		t.Fatalf("lightNeeds 有 %d 個 key，lightNames 有 %d 個名稱，集合應恰好相等", len(lightNeeds), len(names))
	}
	for _, name := range names {
		if _, ok := lightNeeds[name]; !ok {
			t.Errorf("lightNeeds 缺少站名 %q", name)
		}
	}
}

func TestClearMapFrame(t *testing.T) {
	cases := []struct {
		lines int
		want  string
	}{
		{3, "\x1b[3A\r\x1b[2K\x1b[1B\r\x1b[2K\x1b[1B\r\x1b[2K\x1b[2A"},
		{1, "\x1b[1A\r\x1b[2K"},
	}
	for _, c := range cases {
		var b bytes.Buffer
		clearMapFrame(&b, c.lines)
		if b.String() != c.want {
			t.Errorf("clearMapFrame(lines=%d) = %q，預期 %q", c.lines, b.String(), c.want)
		}
	}
}
