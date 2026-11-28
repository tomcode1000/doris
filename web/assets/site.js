// Doris site: live data from /api/diary and /api/cases.
// Scammer text is untrusted: everything is inserted as plain text (textContent), never parsed as HTML.
(function () {
  "use strict";
  const KIND = {
    case: "Case opened", letter: "Letter sent", scammer: "Scammer reply",
    trap: "Link examined", report: "Site reported", canary: "Fake login came back",
  };
  const FILTERS = ["all", "case", "letter", "scammer", "trap", "report", "canary"];

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function when(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function kindLabel(k) { const t = String(k || "other").replace(/_/g, " "); return t.charAt(0).toUpperCase() + t.slice(1); }
  async function getJSON(url) {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(url + " " + r.status);
    return r.json();
  }
  function setText(id, v) { const n = document.getElementById(id); if (n) n.textContent = v; }

  // ---------- landing ----------
  async function landing() {
    try {
      const d = await getJSON("/api/diary");
      const s = d.stats || {};
      setText("n-cases", d.cases ?? 0);
      setText("l-cases", (d.cases === 1) ? "case" : "cases");
      setText("n-letters", s.doris_letters ?? 0);
      setText("n-links", s.traps_visited ?? 0);
      setText("n-reported", s.reported ?? 0);
      const letter = (d.diary || []).find((e) => e.kind === "letter");
      if (letter) {
        setText("latest-letter", letter.text);
        setText("latest-letter-meta", (letter.case ? letter.case.replace("case-", "Case ") + " · " : "") + when(letter.at));
      }
      chain(d.ledger);
    } catch (e) { /* page still reads fine with the static fallback copy */ }
  }

  function chain(l) {
    const box = document.getElementById("chain");
    if (!box || !l) return;
    box.replaceChildren(el("span", "dot" + (l.intact ? "" : " bad")),
      el("span", null, l.intact
        ? `Tamper-evident log intact · ${l.entries} entries · latest ${String(l.head).slice(0, 10)}`
        : "Log chain check FAILED"));
  }

  // ---------- diary ----------
  async function diary() {
    const list = document.getElementById("timeline");
    const bar = document.getElementById("filters");
    let entries = [];
    let active = "all";
    function render() {
      list.replaceChildren();
      const shown = entries.filter((e) => active === "all" || e.kind === active);
      if (!shown.length) { list.append(el("li", "empty", "Nothing here yet.")); return; }
      for (const e of shown) {
        const li = el("li", "entry" + (e.kind === "letter" ? " letter-entry" : "") + (e.kind === "scammer" ? " scammer" : ""));
        const head = el("div", "entry-head");
        head.append(el("span", "entry-kind", KIND[e.kind] || e.kind), el("span", "entry-time", when(e.at)));
        if (e.kind === "scammer") head.append(el("span", "tag untrusted", "Untrusted"));
        if (e.case) {
          const a = el("a", "entry-case", e.case.replace("case-", "CASE "));
          a.href = "/case?id=" + encodeURIComponent(e.case);
          head.append(a);
        }
        li.append(head, el("div", "entry-text", e.text));
        list.append(li);
      }
    }
    for (const f of FILTERS) {
      const b = el("button", "chip", f === "all" ? "All" : KIND[f]);
      b.type = "button";
      b.setAttribute("aria-pressed", String(f === active));
      b.addEventListener("click", () => {
        active = f;
        for (const c of bar.children) c.setAttribute("aria-pressed", String(c === b));
        render();
      });
      bar.append(b);
    }
    try {
      const d = await getJSON("/api/diary");
      entries = d.diary || [];
      chain(d.ledger);
    } catch (e) { list.replaceChildren(el("li", "empty", "Doris is having a nap. Try again in a moment.")); return; }
    render();
  }

  // ---------- case file ----------
  async function caseFile() {
    const root = document.getElementById("case-root");
    const id = new URLSearchParams(location.search).get("id");
    let cases = [];
    try { cases = await getJSON("/api/cases"); } catch (e) { root.replaceChildren(el("p", "empty", "Case files are unavailable right now.")); return; }
    const c = cases.find((x) => x.case === id) || (!id && cases[0]);
    if (!c) {
      root.replaceChildren(el("p", "empty", cases.length ? "No case with that number." : "No cases yet."));
      if (cases.length) root.append(caseList(cases));
      return;
    }
    document.title = c.case.replace("case-", "Case ") + " · Doris";
    setText("case-title", c.case.replace("case-", "CASE "));
    setText("case-status", c.status);
    setText("f-type", kindLabel(c.kind) + " scam");
    setText("f-opened", when(c.opened_at));
    setText("f-letters", c.letters);
    setText("f-replies", c.scammer_replies);
    const thread = document.getElementById("thread");
    thread.replaceChildren();
    for (const h of c.history) {
      const m = el("article", "msg " + (h.who === "doris" ? "doris" : "scammer"));
      const head = el("div", "msg-head");
      head.append(el("span", null, (h.who === "doris" ? "Doris wrote" : "Received · sender withheld") + " · " + when(h.at)));
      if (h.who !== "doris") head.append(el("span", "tag untrusted", "Untrusted"));
      m.append(head, el("div", "msg-body", h.text));
      thread.append(m);
    }
    const log = document.getElementById("log-body");
    log.replaceChildren();
    for (const e of c.log) {
      const tr = el("tr");
      tr.append(el("td", null, when(e.at)), el("td", null, e.kind.replace(/_/g, " ")), el("td", "mono", e.hash));
      log.append(tr);
    }
    if (cases.length > 1) { const o = document.getElementById("other-cases"); o.append(el("p", "eyebrow", "Other cases"), caseList(cases.filter((x) => x !== c))); }
  }

  function caseList(cases) {
    const wrap = el("div", "case-list");
    for (const c of cases) {
      const a = el("a", "case-card");
      a.href = "/case?id=" + encodeURIComponent(c.case);
      a.append(el("div", "mono", c.case.replace("case-", "CASE ")),
        el("div", "h-md", kindLabel(c.kind) + " scam"),
        el("div", "muted", c.status + " · " + when(c.opened_at)));
      wrap.append(a);
    }
    return wrap;
  }

  const page = document.body.dataset.page;
  if (page === "landing") landing();
  if (page === "diary") diary();
  if (page === "case") caseFile();
})();
