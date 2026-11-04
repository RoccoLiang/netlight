# netlight 網路紅綠燈

> **English summary** — netlight is a one-shot network "traffic light" for non-technical users. Run it once to see which segment is likely broken (local link, router, internet, DNS or websites) and who to call. Single binary, no installation, no admin rights. Windows / macOS / Linux. The user interface is in Traditional Chinese (Taiwan).

不需要懂網路，執行一次，就能幫你判斷網路可能斷在哪一段、該找誰處理。

支援macOS、Windows、Linux（以Ubuntu為主），單一執行檔，不需要安裝，也不需要系統管理員權限。

```
網路紅綠燈 netlight v1.2.0 · macOS · 2026-11-02 14:03
🟢 正常 本機網路　Wi-Fi 192.168.1.23
🟢 正常 路由器　　192.168.1.1 正常
🟢 正常 對外連線　可連到網際網路
🔴 故障 網址查詢　無法查詢網址（DNS 故障）
⚪ 略過 網站連線　需要先能查網址
結論：路由器負責的查網址功能（DNS）沒有正常回應，可能是路由器或電信業者的 DNS 故障。
建議：將路由器拔電 30 秒再插回；仍不行請聯絡網路業者（如中華電信）。
```

（上面是文字版的輸出範例；網頁版會以按鈕與燈號顯示同樣的結果。）

## 怎麼執行

到 [Releases](https://github.com/RoccoLiang/netlight/releases) 下載對應平台的檔案：

| 平台 | 方法 |
|---|---|
| Windows | 下載`netlight-windows-amd64.zip`，解壓縮後雙擊`netlight-windows-amd64.exe`，會自動開啟網頁版。若出現SmartScreen，按「其他資訊」→「仍要執行」。 |
| macOS | 下載對應晶片的tar.gz（Apple晶片用arm64、Intel用amd64），雙擊解壓縮後，在「終端機」先`cd`進入解壓出的資料夾（例如`cd ~/Downloads/netlight-darwin-arm64`），再執行`./netlight-darwin-arm64 --web`。Intel Mac請把指令中的arm64換成amd64。第一次若被擋，到「系統設定 → 隱私權與安全性」按「仍要打開」。IT派送可用`xattr -d com.apple.quarantine netlight-darwin-arm64`。 |
| Ubuntu | 下載netlight-linux-amd64.tar.gz，執行`tar xzf netlight-linux-amd64.tar.gz && cd netlight-linux-amd64 && ./netlight-linux-amd64 --web`（沒有桌面環境時去掉`--web`改用文字版）。 |

上表的方法都使用網頁版：按一個按鈕就會檢查，並可一鍵複製回報文字。

- **什麼時候開網頁版**：指定`--web`時一定使用網頁版。Windows從檔案總管雙擊、而且沒有帶任何參數時，也會自動開網頁版；從命令列執行、或帶了任何參數（包括`--no-pause`）時，是文字版。
- **想直接看文字結果**：macOS、Linux把指令中的`--web`去掉；Windows在PowerShell進入資料夾後執行`.\netlight-windows-amd64.exe`。
- **瀏覽器沒有打開時**：Windows雙擊自動開網頁版失敗，會改用文字版顯示結果；指定`--web`時則會在終端機印出本機網址，可以自己貼到瀏覽器。
- **什麼時候結束**：關閉最後一個網頁分頁後，通常約5秒結束；瀏覽器沒有送出關閉通知時，約90秒後結束。啟動後1分鐘內都沒有打開網頁，也會自動結束。檢查進行中不會結束。

## 燈號

預設五盞；設定單位網路檢查點時多一盞「單位網路」，位於路由器與對外連線之間。

| 燈 | 檢查內容 |
|---|---|
| 本機網路 | 電腦有沒有拿到可用的IP |
| 路由器 | 有沒有預設閘道、閘道有沒有回應（ping或TCP任一種有回應即可，Windows、Linux另外參考ARP；不回應但網路正常時仍為綠燈；讀不到路由器資訊時為黃燈） |
| 單位網路（有設定時） | 設定檔列出的單位網路節點（防火牆、GSN DNS等）是否有回應；ping、DNS查詢或TCP連線 |
| 對外連線 | 能不能連到網際網路：用TCP 443直接連1.1.1.1、8.8.8.8，查詢公共DNS，以及預設網站有沒有回應，任一項成立即可；有VPN或代理會註明；技術細節附上往1.1.1.1的路由追蹤 |
| 網址查詢 | 查網址的服務是否正常：DNS回覆「網址不存在」仍視為服務正常；本機DNS不通但可經由代理連上網站時，顯示「由代理伺服器代查」 |
| 網站連線 | 預設網站（Google、Cloudflare、Microsoft、政府入口網）或設定檔的網站，能不能建立HTTPS連線並取得HTTP回應；3xx、4xx也算連得上，不保證網頁功能正常 |

🟢 正常　🟡 注意　🔴 故障　⚪ 略過（前一段已經壞了，不必再猜）

舊版Windows主控台無法顯示emoji，會自動改用`[正常] [注意] [故障] [略過]`。

## 可能的結論

結論是依各項檢查結果推估最可能的原因。同一個結論碼會依網路環境（例如VPN、手機熱點、DNS設定）提供不同的原因說明與處理建議，請以畫面上的完整文字為準。

| 結論碼 | 意思 |
|---|---|
| `OK` | 本次檢查沒有發現問題；只測自訂網站時，不代表已確認網際網路正常 |
| `NO_LINK` | 電腦沒連上網路 |
| `NO_DHCP` | 沒有從路由器拿到位址，或一般IPv4網路有位址卻找不到路由器（沒有預設閘道），且完全連不出去 |
| `PORTAL` | 需要先登入Wi-Fi網頁（飯店、咖啡廳） |
| `CLOCK` | 疑似電腦時間不正確（多個網站的憑證日期驗證失敗，或時間明顯不對且有憑證錯誤） |
| `VPN_BROKEN` | VPN異常 |
| `PROXY` | 代理伺服器連不出去 |
| `PROXY_PAC` | 使用自動代理設定（PAC），但程式不執行PAC，直接測試網站也都沒有回應，無法確認瀏覽器經由PAC的實際結果 |
| `ISP` | 路由器正常但出不去，找網路業者（手機熱點時改為請你檢查手機的行動數據；單位網路有節點回應時，改為請你聯絡單位資訊人員） |
| `ROUTER_OR_ISP` | 路由器或電信線路 |
| `ORG_NETWORK` | 單位設定的網路節點都沒有回應，問題可能在路由器、單位內部網路或出口設備 |
| `DNS` | 查網址的服務故障（會依VPN、DNS設定說明可能原因） |
| `TLS_INTERCEPT` | 疑似加密連線被攔截或憑證不受信任，常見原因是防毒軟體或公司資安設備 |
| `FILTERED` | 網站連線被過濾 |
| `UNSTABLE` | 網路時好時壞，部分連線中斷或逾時 |
| `SITE` | 網路大致正常，但一個或多個目標網站連線異常 |
| `UNKNOWN` | 證據不足 |

## 公司使用：設定檔

把`netlight.json`放在執行檔旁邊或目前目錄（兩處都有時，只讀執行檔旁邊的那份），結論不是`OK`、而且設定檔有對應的聯絡窗口時，會在結論下方顯示窗口；也可以加測內部網站。範例見 [`netlight.example.json`](netlight.example.json)。

- `org`：公司名稱，會顯示在聯絡窗口前。
- `contact`：key是結論碼（大小寫皆可，如`dns`、`isp`、`vpn_broken`），`proxy_pac`找不到時會改用`proxy`，找不到時用`default`。
- `targets`：額外要測的網站，必須是`https://`。
- `replace_default_targets`：設為`true`時，網站連線與其網址查詢只測自訂網站；公共IP、公共DNS與Wi-Fi登入頁的檢查仍會照常進行。
- `show_public_ip`：是否在技術細節顯示對外IP（預設true；設為false時不會查詢）。
- `checkpoints`：單位網路的檢查點，每個包含`name`、`host`、`check`（`ping`、`dns`、`tcp:<埠>`），最多10個。

### 政府機關（GSN）範例

```json
{
  "checkpoints": [
    { "name": "GSN DNS 1", "host": "210.69.1.1", "check": "dns" },
    { "name": "GSN DNS 2", "host": "210.69.2.1", "check": "dns" }
  ]
}
```

210.69.1.1、210.69.2.1是政府服務網（GSN）的DNS伺服器；請依單位的實際網路調整，也可以加入單位防火牆或內部DNS。

JSON格式錯誤（含結尾有多餘內容）、欄位名稱打錯、`contact`用了不認得的結論碼、或`replace_default_targets`為`true`但沒有`targets`，程式會直接報錯並以結束碼3結束。

## 隱私與連線清單

netlight沒有遙測，不會把診斷結果回傳給開發者或任何第三方；結果只顯示在你的畫面上。各項探測就像一般連線：對方會看到連線的來源IP（經由代理時是代理的出口IP）。DNS查詢會送出要查的網址；網站與對外IP的HTTPS請求會帶上程式版本（User-Agent `netlight/<版本>`）。執行時會連線到：

| 連線對象 | 用途 |
|---|---|
| 系統的網址查詢（依電腦的DNS設定） | 查詢下列網站的網址 |
| 電腦設定的代理伺服器（若有） | 網站、對外IP與登入頁檢查依協定（HTTP／HTTPS）與代理例外清單決定是否經由代理；自動代理設定（PAC）只讀取設定，不下載或執行腳本，探測採直接連線 |
| 1.1.1.1、8.8.8.8（TCP 443） | 測試能否直接連到網際網路（只建立連線，不傳送資料） |
| 8.8.8.8、1.1.1.1（DNS，UDP 53） | 測試公共DNS（查詢`www.google.com`） |
| 電腦設定的DNS伺服器（UDP 53，最多前3台） | 逐台測試DNS設定（查詢`www.google.com`） |
| www.google.com、www.cloudflare.com、www.microsoft.com、www.gov.tw（HTTPS） | 測試網站連線（設定檔可加入或取代） |
| connectivitycheck.gstatic.com、captive.apple.com（HTTP） | 偵測是否需要先登入Wi-Fi |
| 上述預設網站的`/cdn-cgi/trace` | 取得對外IP（設定檔`show_public_ip: false`可關閉） |
| 路由器（ICMP、TCP 80／443／53；Windows、Linux另有ARP） | 確認路由器是否回應 |
| 1.1.1.1（ICMP，TTL 1～15） | 路由追蹤：記錄往網際網路經過的節點，作為技術細節 |
| 設定檔列出的單位網路檢查點（若有） | 依設定以ping、DNS（查詢`www.google.com`）或TCP連線確認是否有回應 |

網頁版只在本機`127.0.0.1`開啟，其他電腦無法連入。

## 參數

| 參數 | 說明 |
|---|---|
| `--detail` | 每盞燈底下列出技術證據（IP、延遲、錯誤類型） |
| `--json` | JSON輸出，給腳本或回報問題用 |
| `--plain` | 不用emoji與顏色 |
| `--no-pause` | Windows雙擊執行時，結束不等待按鍵（帶了這個參數就不會自動開網頁版） |
| `--config PATH` | 指定設定檔 |
| `--web` | 在瀏覽器開啟本機網頁版，按鈕操作、可複製回報文字 |
| `--version` | 顯示版本 |

`--detail`、`--json`、`--plain`不適用於網頁版：指定`--web`時會忽略它們。

結束碼（文字版與`--json`）：`0`正常、`1`找到問題、`2`無法判斷（`UNKNOWN`、`PROXY_PAC`）、`3`設定檔錯誤。網頁版的結束碼不代表診斷結果：`0`是正常關閉、`2`是網頁服務發生錯誤、`3`是設定檔錯誤。

## 開發

```
go test -race ./...          # 單元測試＋實機整合測試
go test -short ./...         # 略過需要網路的整合測試
go test ./... -update        # 重新產生 testdata/*.golden
./build.sh v1.2.0            # 交叉編譯並打包到 dist/（各平台執行檔、zip／tar.gz、SHA256SUMS）
```

發版：把`v*`格式的tag推送到GitHub（`git push github <tag>`），GitHub Actions會自動建置、附上建置來源證明並建立release；推送到Gitea不會觸發這個流程。變更紀錄見 [CHANGELOG.md](CHANGELOG.md)，安全問題回報方式見 [SECURITY.md](SECURITY.md)。

設計參考了 [heymaikol/network-doctor](https://github.com/heymaikol/network-doctor)（Apache-2.0）的分層診斷概念，程式碼為獨立撰寫。

## 授權

[MIT](LICENSE)
