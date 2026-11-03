# netlight 網路紅綠燈

> **English summary** — netlight is a one-shot network "traffic light" for non-technical users. Run it once to see which segment is broken (local link, router, internet, DNS or websites) and who to call. Single binary, no installation, no admin rights. Windows / macOS / Linux. The user interface is in Traditional Chinese (Taiwan).

不需要懂網路，執行一次就知道：**網路斷在哪一段、該找誰處理**。

支援 macOS、Windows、Linux（以 Ubuntu 為主），單一執行檔，不需要安裝，也不需要系統管理員權限。

```
網路紅綠燈 netlight v1.0.0 · macOS · 2026-11-02 14:03
🟢 正常 本機網路　Wi-Fi 192.168.1.23
🟢 正常 路由器　　192.168.1.1 正常
🟢 正常 對外連線　可連到網際網路
🔴 故障 網址查詢　無法查詢網址（DNS 故障）
⚪ 略過 網站連線　需要先能查網址
結論：路由器負責的查網址功能（DNS）沒有正常回應，可能是路由器或電信業者的 DNS 故障。
建議：將路由器拔電 30 秒再插回；仍不行請聯絡網路業者（如中華電信）。
```

下載：到 [Releases](https://github.com/RoccoLiang/netlight/releases) 下載對應平台的檔案。

## 怎麼執行

| 平台 | 方法 |
|---|---|
| Windows | 下載 `netlight-windows-amd64.zip`，解壓縮後雙擊 `netlight-windows-amd64.exe`，會自動開啟網頁版。若出現 SmartScreen，按「其他資訊」→「仍要執行」。 |
| macOS | 下載對應晶片的 tar.gz（Apple 晶片用 arm64、Intel 用 amd64），雙擊解壓縮後，在「終端機」先 `cd` 進入解壓出的資料夾（例如 `cd ~/Downloads/netlight-darwin-arm64`），再執行 `./netlight-darwin-arm64 --web`。Intel Mac 請把指令中的 arm64 換成 amd64。第一次若被擋，到「系統設定 → 隱私權與安全性」按「仍要打開」。IT 派送可用 `xattr -d com.apple.quarantine netlight-darwin-arm64`。 |
| Ubuntu | 下載 netlight-linux-amd64.tar.gz，執行 `tar xzf netlight-linux-amd64.tar.gz && cd netlight-linux-amd64 && ./netlight-linux-amd64 --web`（沒有桌面環境時去掉 `--web` 改用文字版）。 |

不想看終端機文字，可以改用網頁版：在上表的執行指令加上 `--web`，會自動開啟瀏覽器。網頁版按一個按鈕就會檢查，並可一鍵複製回報文字。關閉網頁分頁後，程式會自動結束。Windows 從檔案總管雙擊時會自動使用網頁版；從命令列執行則是文字版。

## 五盞燈

| 燈 | 檢查內容 |
|---|---|
| 本機網路 | 電腦有沒有拿到可用的 IP |
| 路由器 | 有沒有預設閘道、閘道有沒有回應（不回 ping 但網路正常時仍為綠燈） |
| 對外連線 | 能不能用 TCP 443 直接連到 1.1.1.1、8.8.8.8，或查詢公共 DNS；有 VPN 或代理會註明 |
| 網址查詢 | 系統 DNS 能不能查到網址 |
| 網站連線 | 能不能用 HTTPS 開啟 Google、Cloudflare、Microsoft、政府入口網 |

🟢 正常　🟡 注意　🔴 故障　⚪ 略過（前一段已經壞了，不必再猜）

舊版 Windows 主控台無法顯示 emoji，會自動改用 `[正常] [注意] [故障] [略過]`。

## 可能的結論

| 結論碼 | 意思 |
|---|---|
| `OK` | 網路正常 |
| `NO_LINK` | 電腦沒連上網路 |
| `NO_DHCP` | 沒有從路由器拿到位址 |
| `PORTAL` | 需要先登入 Wi-Fi 網頁（飯店、咖啡廳） |
| `CLOCK` | 電腦時間不正確 |
| `VPN_BROKEN` | VPN 異常 |
| `PROXY` | 代理伺服器連不出去 |
| `PROXY_PAC` | 使用自動代理設定（PAC），直接連線也不通，無法判斷是代理還是線路 |
| `ISP` | 路由器正常但出不去，找網路業者 |
| `ROUTER_OR_ISP` | 路由器或電信線路 |
| `DNS` | 查網址的服務故障 |
| `TLS_INTERCEPT` | 加密連線被防毒或資安設備攔截 |
| `FILTERED` | 網站連線被過濾 |
| `UNSTABLE` | 網路時好時壞，部分連線中斷或逾時 |
| `SITE` | 網路正常，是某個網站本身的問題 |
| `UNKNOWN` | 證據不足 |

## 公司使用：設定檔

把 `netlight.json` 放在執行檔旁邊（或目前目錄），就會在結論下方顯示公司的聯絡窗口，並加測內部網站。範例見 [`netlight.example.json`](netlight.example.json)。

- `org`：公司名稱，會顯示在聯絡窗口前。
- `contact`：key 是結論碼（大小寫皆可，如 `dns`、`isp`、`vpn_broken`），`proxy_pac` 找不到時會改用 `proxy`，找不到時用 `default`。
- `targets`：額外要測的網站，必須是 `https://`。
- `replace_default_targets`：設為 `true` 時只測自訂網站。
- `show_public_ip`：是否在技術細節顯示對外 IP（預設 true；設為 false 時不會查詢）。

欄位名稱打錯、`contact` 用了不認得的結論碼、或 `replace_default_targets` 為 `true` 但沒有 `targets`，程式會直接報錯並以結束碼 3 結束。

## 隱私與連線清單

netlight 沒有遙測，不會把診斷結果回傳給開發者或任何第三方；結果只顯示在你的畫面上。下列探測對象會像一般連線一樣，看到你的對外 IP、查詢的網址與程式版本（User-Agent）。執行時會連線到：

| 連線對象 | 用途 |
|---|---|
| 系統的網址查詢（依電腦的 DNS 設定） | 查詢下列網站的網址 |
| 電腦設定的代理伺服器（若有） | 網站、對外 IP 與登入頁檢查會經由代理；自動代理設定（PAC）只讀取設定，不下載或執行腳本 |
| 1.1.1.1、8.8.8.8（TCP 443） | 測試能否直接連到網際網路 |
| 8.8.8.8、1.1.1.1（DNS，UDP 53） | 測試公共 DNS |
| 電腦設定的 DNS 伺服器（UDP 53，最多前 3 台） | 逐台測試 DNS 設定 |
| www.google.com、www.cloudflare.com、www.microsoft.com、www.gov.tw（HTTPS） | 測試網站連線（設定檔可加入或取代） |
| connectivitycheck.gstatic.com、captive.apple.com（HTTP） | 偵測是否需要先登入 Wi-Fi |
| 上述預設網站的 `/cdn-cgi/trace` | 取得對外 IP（設定檔 `show_public_ip: false` 可關閉） |
| 路由器（ICMP、TCP 80／443／53、ARP） | 確認路由器是否回應 |

網頁版只在本機 `127.0.0.1` 開啟，其他電腦無法連入。

## 參數

| 參數 | 說明 |
|---|---|
| `--detail` | 每盞燈底下列出技術證據（IP、延遲、錯誤類型） |
| `--json` | JSON 輸出，給腳本或回報問題用 |
| `--plain` | 不用 emoji 與顏色 |
| `--no-pause` | Windows 雙擊執行時，結束不等待按鍵 |
| `--config PATH` | 指定設定檔 |
| `--web` | 在瀏覽器開啟本機網頁版，按鈕操作、可複製回報文字 |
| `--version` | 顯示版本 |

結束碼：`0` 正常、`1` 找到問題、`2` 無法判斷（`UNKNOWN`、`PROXY_PAC`）、`3` 設定檔錯誤。

## 開發

```
go test -race ./...          # 單元測試＋實機整合測試
go test -short ./...         # 略過需要網路的整合測試
go test ./... -update        # 重新產生 testdata/*.golden
./build.sh v1.0.0            # 交叉編譯到 dist/
```

設計參考了 [heymaikol/network-doctor](https://github.com/heymaikol/network-doctor)（Apache-2.0）的分層診斷概念，程式碼為獨立撰寫。

## 授權

[MIT](LICENSE)
