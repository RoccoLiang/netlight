# 安全政策（Security Policy）

## 回報漏洞

請**不要**在公開的 Issue 回報安全漏洞。請使用 GitHub 的私密回報功能：
到本 repo 的「Security」分頁 →「Report a vulnerability」。

Please do not report security vulnerabilities in public issues. Use GitHub private
vulnerability reporting: Security tab → "Report a vulnerability".

## 安全邊界

- netlight 只做連線測試，不修改任何系統或網路設定，不需要系統管理員權限。
- 網頁版（`--web`）只在本機 `127.0.0.1` 的隨機埠開啟，網址含隨機 token；伺服器會檢查 Host；非 GET 請求若帶有 Origin，必須與本機網址相符；並套用嚴格的 Content-Security-Policy。其他電腦無法連入。
- 沒有遙測，不會把診斷結果回傳給開發者或任何第三方。連線對象見 README 的「隱私與連線清單」。

## 支援版本

只對最新的 release 提供安全修正。
