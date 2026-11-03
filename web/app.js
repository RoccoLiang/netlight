// 網路紅綠燈網頁版（不使用 innerHTML，全部以 textContent 更新）
"use strict";

(function () {
	var STATE_TEXT = { green: "正常", yellow: "注意", red: "故障", skip: "略過" };
	var MARK_CHAR = { green: "✓", yellow: "!", red: "✕", skip: "–" };

	// stage 事件與燈的對應：「網址查詢」要 dns 與 public_dns 都完成、「網站連線」要 sites 與 captive 都完成
	var STAGE_LIGHTS = {
		local: 0,
		gateway: 1,
		direct: 2,
		dns: 3,
		public_dns: 3,
		sites: 4,
		captive: 4
	};
	var LIGHT_STAGES = [
		["local"],
		["gateway"],
		["direct"],
		["dns", "public_dns"],
		["sites", "captive"]
	];

	var runBtn = document.getElementById("run");
	var copyBtn = document.getElementById("copy");
	var byeBtn = document.getElementById("bye");
	var copyNote = document.getElementById("copy-note");
	var verdictText = document.getElementById("verdict-text");
	var verdictAction = document.getElementById("verdict-action");
	var contactWrap = document.getElementById("contact-wrap");
	var verdictContact = document.getElementById("verdict-contact");
	var evidence = document.getElementById("evidence");
	var mainEl = document.getElementById("main");
	var endedEl = document.getElementById("ended");

	var lights = [];
	for (var i = 0; i < 5; i++) {
		lights.push({
			mark: document.getElementById("mark-" + i),
			status: document.getElementById("status-" + i),
			summary: document.getElementById("summary-" + i)
		});
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
		for (var i = 0; i < 5; i++) {
			var l = lights[i];
			l.mark.textContent = "○";
			l.mark.className = "mark mark-pending";
			l.status.textContent = "等待中";
			l.summary.textContent = "";
		}
	}

	function setChecking() {
		for (var i = 0; i < 5; i++) {
			var l = lights[i];
			l.mark.textContent = "○";
			l.mark.className = "mark mark-checking";
			l.status.textContent = "檢查中";
			l.summary.textContent = "";
		}
	}

	// 對應的探測完成後，該盞燈轉為「已完成，判斷中」（不經 aria-live 播報，避免太吵）
	function markStageDone(stage) {
		var i = STAGE_LIGHTS[stage];
		if (i === undefined) {
			return;
		}
		stageSeen[stage] = true;
		var need = LIGHT_STAGES[i];
		for (var n = 0; n < need.length; n++) {
			if (!stageSeen[need[n]]) {
				return;
			}
		}
		var l = lights[i];
		l.mark.textContent = "●";
		l.mark.className = "mark mark-stage-done";
		l.status.textContent = "已完成，判斷中";
	}

	function setButtons() {
		runBtn.disabled = running;
		runBtn.textContent = running ? "檢查中…約 10 秒" : (hasResult ? "重新檢查" : "開始檢查");
		copyBtn.disabled = running || !reportText;
	}

	function showResult(data) {
		running = false;
		hasResult = true;
		var result = data && data.result ? data.result : {};
		var lightsData = result.lights || [];
		for (var i = 0; i < 5; i++) {
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

	function copyByFallback() {
		var ta = document.createElement("textarea");
		ta.value = reportText;
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

	function noteCopied() {
		copyNote.textContent = "已複製";
		if (copyTimer) {
			clearTimeout(copyTimer);
		}
		copyTimer = setTimeout(function () {
			copyNote.textContent = "";
		}, 3000);
	}

	function copyReport() {
		if (!reportText) {
			return;
		}
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(reportText).then(function () {
				noteCopied();
			}, function () {
				if (copyByFallback()) {
					noteCopied();
				} else {
					copyNote.textContent = "複製失敗，請改用「技術細節」手動複製";
				}
			});
			return;
		}
		if (copyByFallback()) {
			noteCopied();
		} else {
			copyNote.textContent = "複製失敗，請改用「技術細節」手動複製";
		}
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
	byeBtn.addEventListener("click", endProgram);

	beat();
	beatTimer = setInterval(beat, 10000);
})();
