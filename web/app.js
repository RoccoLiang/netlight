// 網路紅綠燈網頁版（不使用 innerHTML，全部以 textContent 更新）
"use strict";

(function () {
	var STATE_TEXT = { green: "正常", yellow: "注意", red: "故障", skip: "略過" };
	var MARK_CHAR = { green: "✓", yellow: "!", red: "✕", skip: "–" };

	// 各燈需要哪些 stage 都完成才轉為「已完成，判斷中」
	var LIGHT_NEEDS = {
		"本機網路": ["local"],
		"路由器": ["gateway"],
		"單位網路": ["checkpoints"],
		"對外連線": ["direct"],
		"網址查詢": ["dns", "public_dns"],
		"網站連線": ["sites", "captive"]
	};
	var DEFAULT_NAMES = ["本機網路", "路由器", "對外連線", "網址查詢", "網站連線"];
	// 伺服器提供的燈名（api/layout 回應通過格式檢查時更新），每次檢查開始時恢復
	var layoutNames = DEFAULT_NAMES;

	var runBtn = document.getElementById("run");
	var copyBtn = document.getElementById("copy");
	var copyFullBtn = document.getElementById("copy-full");
	var byeBtn = document.getElementById("bye");
	var copyNote = document.getElementById("copy-note");
	var verdictText = document.getElementById("verdict-text");
	var verdictAction = document.getElementById("verdict-action");
	var contactWrap = document.getElementById("contact-wrap");
	var verdictContact = document.getElementById("verdict-contact");
	var evidence = document.getElementById("evidence");
	var mainEl = document.getElementById("main");
	var endedEl = document.getElementById("ended");

	var lightsEl = document.getElementById("lights");
	var lights = [];

	// buildRows：依燈名建立燈號列（結構與原本的靜態 <li> 相同）
	function buildRows(names) {
		lights = [];
		lightsEl.textContent = "";
		for (var i = 0; i < names.length; i++) {
			var li = document.createElement("li");
			var mark = document.createElement("span");
			mark.className = "mark mark-pending";
			mark.setAttribute("aria-hidden", "true");
			mark.textContent = "○";
			var body = document.createElement("span");
			body.className = "light-body";
			var line = document.createElement("span");
			line.className = "light-line";
			var name = document.createElement("span");
			name.className = "light-name";
			name.textContent = names[i];
			var status = document.createElement("span");
			status.className = "light-status";
			status.textContent = "等待中";
			line.appendChild(name);
			line.appendChild(status);
			var summary = document.createElement("span");
			summary.className = "light-summary";
			body.appendChild(line);
			body.appendChild(summary);
			li.appendChild(mark);
			li.appendChild(body);
			lightsEl.appendChild(li);
			lights.push({ name: names[i], mark: mark, status: status, summary: summary });
		}
	}

	// rowsMatch：目前各列的數量與名稱依序都等於 names 時回傳 true
	function rowsMatch(names) {
		if (lights.length !== names.length) {
			return false;
		}
		for (var i = 0; i < names.length; i++) {
			if (lights[i].name !== names[i]) {
				return false;
			}
		}
		return true;
	}

	// 頁面識別：每次載入重新產生，用於心跳與關閉通知的亂序防護
	function makePageId() {
		var b = new Uint8Array(16);
		crypto.getRandomValues(b);
		var s = "";
		for (var i = 0; i < b.length; i++) {
			var h = b[i].toString(16);
			s += h.length < 2 ? "0" + h : h;
		}
		return s;
	}
	var pageId = makePageId();

	var reportText = "";
	var safeText = "";
	var running = false;
	var hasResult = false;
	var copyTimer = null;
	var beatTimer = null;
	var stageSeen = {};

	function setLight(i, status, summary) {
		var l = lights[i];
		l.mark.textContent = MARK_CHAR[status] || "–";
		l.mark.className = "mark mark-" + status;
		l.status.textContent = STATE_TEXT[status] || "略過";
		l.summary.textContent = summary || "";
	}

	function setPending() {
		for (var i = 0; i < lights.length; i++) {
			var l = lights[i];
			l.mark.textContent = "○";
			l.mark.className = "mark mark-pending";
			l.status.textContent = "等待中";
			l.summary.textContent = "";
		}
	}

	function setChecking() {
		for (var i = 0; i < lights.length; i++) {
			var l = lights[i];
			l.mark.textContent = "○";
			l.mark.className = "mark mark-checking";
			l.status.textContent = "檢查中";
			l.summary.textContent = "";
		}
	}

	// 對應的探測完成後，該盞燈轉為「已完成，判斷中」（不經 aria-live 播報，避免太吵）
	function markStageDone(stage) {
		stageSeen[stage] = true;
		for (var i = 0; i < lights.length; i++) {
			var need = LIGHT_NEEDS[lights[i].name];
			if (!need || need.indexOf(stage) < 0) {
				continue;
			}
			var done = true;
			for (var n = 0; n < need.length; n++) {
				if (!stageSeen[need[n]]) {
					done = false;
					break;
				}
			}
			if (done) {
				var l = lights[i];
				l.mark.textContent = "●";
				l.mark.className = "mark mark-stage-done";
				l.status.textContent = "已完成，判斷中";
			}
		}
	}

	function setButtons() {
		runBtn.disabled = running;
		runBtn.textContent = running ? "檢查中…約 10 秒" : (hasResult ? "重新檢查" : "開始檢查");
		copyBtn.disabled = running || !safeText;
		copyFullBtn.disabled = running || !reportText;
	}

	function showResult(data) {
		running = false;
		hasResult = true;
		var result = data && data.result ? data.result : {};
		var lightsData = result.lights || [];
		// 回報的燈號與目前各列不同時，先以回報的名稱重建，避免錯位
		var names = [];
		for (var j = 0; j < lightsData.length; j++) {
			names.push((lightsData[j] || {}).name || "");
		}
		if (!rowsMatch(names)) {
			buildRows(names);
		}
		for (var i = 0; i < lights.length; i++) {
			var l = lightsData[i] || {};
			setLight(i, l.status, l.summary);
		}
		var v = result.verdict || {};
		verdictText.textContent = v.text || "（沒有結論）";
		verdictAction.textContent = v.action || "";
		if (v.contact) {
			var org = v.org || "";
			verdictContact.textContent = org ? "（" + org + "）" + v.contact : v.contact;
			contactWrap.hidden = false;
		} else {
			verdictContact.textContent = "";
			contactWrap.hidden = true;
		}
		renderEvidence(lightsData);
		reportText = data && data.text ? data.text : "";
		safeText = data && data.safe_text ? data.safe_text : "";
	}

	function renderEvidence(lightsData) {
		evidence.textContent = "";
		lightsData.forEach(function (l) {
			var dt = document.createElement("dt");
			dt.textContent = l.name || "";
			evidence.appendChild(dt);
			var dd = document.createElement("dd");
			var ul = document.createElement("ul");
			var ev = l.evidence || [];
			if (ev.length === 0) {
				var none = document.createElement("li");
				none.textContent = "沒有紀錄";
				ul.appendChild(none);
			} else {
				ev.forEach(function (e) {
					var li = document.createElement("li");
					li.textContent = e;
					ul.appendChild(li);
				});
			}
			dd.appendChild(ul);
			evidence.appendChild(dd);
		});
	}

	function showError(message) {
		running = false;
		hasResult = false;
		reportText = "";
		safeText = "";
		setPending();
		evidence.textContent = "";
		verdictText.textContent = message;
		verdictAction.textContent = "";
		verdictContact.textContent = "";
		contactWrap.hidden = true;
	}

	// 讀取 api/run 的 NDJSON 串流：逐行處理 stage 事件，收到 report 事件後 resolve
	function readRunStream(res) {
		return new Promise(function (resolve, reject) {
			var reader = res.body.getReader();
			var decoder = new TextDecoder();
			var buf = "";
			var report = null;
			// 逐行處理：JSON 解析失敗時取消讀取並回報失敗；成功時回 true
			function handleLines(lines) {
				for (var i = 0; i < lines.length; i++) {
					try {
						var ev = JSON.parse(lines[i]);
					} catch (e) {
						return false;
					}
					if (ev.type === "stage") {
						markStageDone(ev.stage);
					} else if (ev.type === "report") {
						report = ev;
					}
				}
				return true;
			}
			function fail() {
				reader.cancel().catch(function () {});
				reject(new Error("failed"));
			}
			function pump() {
				reader.read().then(function (chunk) {
					if (chunk.done) {
						// 防禦：串流結尾最後一行沒有換行時，照常解析
						if (buf.trim() !== "" && !handleLines([buf])) {
							fail();
							return;
						}
						if (report) {
							resolve(report);
						} else {
							reject(new Error("failed"));
						}
						return;
					}
					buf += decoder.decode(chunk.value, { stream: true });
					var lines = buf.split("\n");
					buf = lines.pop();
					if (!handleLines(lines)) {
						fail();
						return;
					}
					pump();
				}, function (err) {
					reject(err);
				});
			}
			pump();
		});
	}

	function startRun() {
		if (running) {
			return;
		}
		running = true;
		setButtons();
		// 每次檢查開始時恢復設定中的燈號列（結果重建成其他數量時回到 layout 的版本）
		if (!rowsMatch(layoutNames)) {
			buildRows(layoutNames);
		}
		setChecking();
		verdictText.textContent = "檢查中，約 10 秒…";
		verdictAction.textContent = "";
		stageSeen = {};
		fetch("api/run", { method: "POST" }).then(function (res) {
			if (res.status === 409) {
				throw new Error("busy");
			}
			if (!res.ok) {
				throw new Error("failed");
			}
			return readRunStream(res);
		}).then(function (data) {
			showResult(data);
			setButtons();
		}).catch(function (err) {
			if (err && err.message === "busy") {
				showError("已有一個檢查正在進行");
			} else {
				showError("檢查失敗，請重新整理頁面再試");
			}
			setButtons();
		});
	}

	// ---- 複製回報 ----

	function copyByFallback(text) {
		var ta = document.createElement("textarea");
		ta.value = text;
		ta.setAttribute("readonly", "");
		ta.className = "offscreen";
		document.body.appendChild(ta);
		ta.select();
		var ok = false;
		try {
			ok = document.execCommand("copy");
		} catch (e) {
			ok = false;
		}
		document.body.removeChild(ta);
		return ok;
	}

	function noteCopied(message) {
		copyNote.textContent = message;
		if (copyTimer) {
			clearTimeout(copyTimer);
		}
		copyTimer = setTimeout(function () {
			copyNote.textContent = "";
		}, 3000);
	}

	// copyText：共用複製流程（clipboard 優先，失敗退回 execCommand）
	function copyText(text, copiedNote) {
		if (!text) {
			return;
		}
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(text).then(function () {
				noteCopied(copiedNote);
			}, function () {
				if (copyByFallback(text)) {
					noteCopied(copiedNote);
				} else {
					copyNote.textContent = "複製失敗，請改用「技術細節」手動複製";
				}
			});
			return;
		}
		if (copyByFallback(text)) {
			noteCopied(copiedNote);
		} else {
			copyNote.textContent = "複製失敗，請改用「技術細節」手動複製";
		}
	}

	function copyReport() {
		copyText(safeText, "已複製摘要");
	}

	function copyFullReport() {
		copyText(reportText, "已複製完整技術資料");
	}

	// ---- 心跳與關閉通知 ----

	function beat() {
		fetch("api/heartbeat?p=" + pageId, { method: "POST" }).catch(function () {});
	}

	document.addEventListener("visibilitychange", function () {
		if (!document.hidden) {
			beat();
		}
	});

	// 關閉通知：keepalive fetch（cors 模式會帶真正的 Origin），
	// 不能用 sendBeacon——無本文 POST 在 no-referrer 下會送 Origin: null 被後端擋掉。
	window.addEventListener("pagehide", function () {
		fetch("api/bye?p=" + pageId, { method: "POST", keepalive: true }).catch(function () {});
	});

	// ---- 結束 netlight ----

	function endProgram() {
		if (beatTimer) {
			clearInterval(beatTimer);
			beatTimer = null;
		}
		fetch("api/shutdown", { method: "POST" }).catch(function () {});
		mainEl.hidden = true;
		endedEl.hidden = false;
	}

	// ---- 事件與啟動 ----

	runBtn.addEventListener("click", startRun);
	copyBtn.addEventListener("click", copyReport);
	copyFullBtn.addEventListener("click", copyFullReport);
	byeBtn.addEventListener("click", endProgram);

	// 啟動：先以預設燈名建立各列，再向伺服器取得設定中的燈名（失敗時維持預設，不顯示錯誤）
	buildRows(DEFAULT_NAMES);
	fetch("api/layout").then(function (res) {
		if (!res.ok) {
			return null;
		}
		return res.json();
	}).then(function (data) {
		var names = data && data.lights;
		if (!Array.isArray(names) || names.length === 0 || !names.every(function (n) { return typeof n === "string"; })) {
			return;
		}
		// 記住伺服器提供的燈名，每次檢查開始時恢復
		layoutNames = names;
		if (!running && !hasResult) {
			buildRows(names);
		}
	}).catch(function () {});

	beat();
	beatTimer = setInterval(beat, 10000);
})();
