網路紅綠燈 netlight（Linux／Ubuntu）

【怎麼用】
1. 解壓縮並進入資料夾：
   tar xzf netlight-linux-amd64.tar.gz
   cd netlight-linux-amd64
2. 網頁版（建議，需要有桌面環境）：
   ./netlight-linux-amd64 --web
   會自動用預設瀏覽器打開，按「開始檢查」即可。關掉網頁後程式會自己結束。
   如果瀏覽器沒有自動打開，把終端機上顯示的網址複製到同一台電腦的瀏覽器。
   如果 1 分鐘內都沒有打開網頁，程式會自動結束，請重新執行。
3. 文字版（沒有桌面環境、或透過 SSH 連線時用這個）：
   ./netlight-linux-amd64
4. 如果出現「Permission denied」，先執行：
   chmod +x netlight-linux-amd64

【注意】
- 不需要安裝，也不需要 sudo。
- 在 WSL 裡執行測到的是虛擬網路，請改用 Windows 版。
- 網頁版只開在本機（127.0.0.1），無法從其他電腦連進來。

【公司使用】
把 netlight.example.json 改名為 netlight.json，填好公司的聯絡窗口，放在執行檔旁邊。

【給 IT 人員】
--detail 顯示技術細節、--json 輸出 JSON、--web 網頁版。
