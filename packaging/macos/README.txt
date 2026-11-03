網路紅綠燈 netlight（macOS）

【先確認你的 Mac】
點左上角蘋果選單 →「關於這台 Mac」：
- 寫「晶片 Apple M…」→ 用 netlight-darwin-arm64
- 寫「處理器 Intel…」→ 用 netlight-darwin-amd64
以下以 arm64 為例，Intel Mac 請把 arm64 換成 amd64。

【怎麼用】
1. 雙擊下載的 .tar.gz 檔，會解壓縮出一個資料夾。
2. 打開「終端機」（在「應用程式」→「工具程式」裡）。
3. 在終端機輸入 cd 再加一個空格，把解壓縮出的資料夾拖進終端機視窗，按 Enter。
4. 網頁版（建議）：輸入下面這行後按 Enter，會自動打開瀏覽器，按「開始檢查」即可。關掉網頁後程式會自己結束。
   ./netlight-darwin-arm64 --web
   文字版：輸入 ./netlight-darwin-arm64 後按 Enter。
   網頁版開著時請不要關閉終端機；如果開啟後 1 分鐘內都沒有打開網頁，程式會自動結束，請重新執行。

【第一次執行被擋住】
如果出現「無法打開」或「Apple 無法檢查是否包含惡意軟體」之類的提示：
1. 先按「完成」關掉提示。
2. 到「系統設定」→「隱私權與安全性」，往下捲到「安全性」，找到 netlight 的訊息，按「仍要打開」。
3. 依畫面完成確認（可能需要輸入電腦密碼），再回到終端機執行一次。
IT 人員也可以直接解除下載標記：xattr -d com.apple.quarantine netlight-darwin-arm64

【公司使用】
把 netlight.example.json 改名為 netlight.json，填好公司的聯絡窗口，放在執行檔旁邊。

【給 IT 人員】
--detail 顯示技術細節、--json 輸出 JSON、--web 網頁版。不需要安裝，也不需要系統管理員權限。
