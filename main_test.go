package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestConfigErrorExit(t *testing.T) {
	sentinel := errors.New("設定檔 bad.json 格式錯誤：unknown field")
	cases := []struct {
		name    string
		asJSON  bool
		wantOut string // stdout
		wantErr string // stderr
	}{
		{"文字模式輸出到 stderr", false, "", sentinel.Error() + "\n"},
		{"JSON 模式輸出到 stdout", true, `{"error":"設定檔 bad.json 格式錯誤：unknown field"}` + "\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := configErrorExit(&out, &errb, sentinel, c.asJSON)
			if code != 3 {
				t.Errorf("結束碼 = %d，預期 3", code)
			}
			if out.String() != c.wantOut {
				t.Errorf("stdout = %q，預期 %q", out.String(), c.wantOut)
			}
			if errb.String() != c.wantErr {
				t.Errorf("stderr = %q，預期 %q", errb.String(), c.wantErr)
			}
		})
	}
}

// TestAutoWeb：雙擊啟動且無任何參數才走自動網頁版
func TestAutoWeb(t *testing.T) {
	cases := []struct {
		nflag, narg int
		doubleClick bool
		want        bool
	}{
		{0, 0, true, true},
		{1, 0, true, false},
		{0, 1, true, false},
		{0, 0, false, false},
	}
	for _, c := range cases {
		if got := autoWeb(c.nflag, c.narg, c.doubleClick); got != c.want {
			t.Errorf("autoWeb(%d, %d, %v) = %v，預期 %v", c.nflag, c.narg, c.doubleClick, got, c.want)
		}
	}
}
