網路紅綠燈 netlight（Windows）

【怎麼用】
1. 先把整個 zip 解壓縮（在 zip 上按右鍵 →「全部解壓縮」），不要直接在 zip 裡面點兩下。
2. 雙擊 netlight-windows-amd64.exe，會自動打開瀏覽器，按「開始檢查」即可。
3. 如果出現藍色的「Windows 已保護您的電腦」：
   按「其他資訊」→「仍要執行」。（這個程式沒有數位簽章，所以 Windows 會提醒。）
4. 同時會出現一個黑色視窗，那是程式本體，請不要關閉；關掉網頁後它會自己結束。
5. 如果瀏覽器打不開，程式會自動改用黑色視窗顯示結果，看完按 Enter 關閉。

【公司使用】
把 netlight.example.json 改名為 netlight.json，填好公司的聯絡窗口，放在執行檔旁邊。

【給 IT 人員】
從命令列執行時是文字版：netlight-windows-amd64.exe --detail（技術細節）、--json（JSON 輸出）、--web（網頁版）。
