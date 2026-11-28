"""Build the inner pages from index.html's shared head, header and footer,
so every page uses exactly the same frame. Run: python scripts/build_pages.py"""

from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "web"
src = (WEB / "index.html").read_text(encoding="utf-8")
head = src[:src.index("<body")]
nav = src[src.index('<header class="nav">'):src.index("</header>") + len("</header>")]
foot = src[src.index('<footer class="foot">'):src.index("</footer>") + len("</footer>")]


def page(name: str, title: str, desc: str, current: str, body: str) -> None:
    h = head.replace("<title>Doris · keeping scammers busy</title>", f"<title>{title}</title>")
    i = h.index('<meta name="description"')
    h = h[:i] + f'<meta name="description" content="{desc}">' + h[h.index(">", i) + 1:]
    n = nav.replace(f'<a href="{current}">', f'<a href="{current}" aria-current="page">')
    (WEB / name).write_text(
        h + f'<body data-page="{Path(name).stem.replace("how-it-works", "how")}">\n\n' + n
        + "\n\n<main>\n" + body + "\n</main>\n\n" + foot
        + '\n\n<script src="/assets/site.js"></script>\n</body>\n</html>\n', encoding="utf-8")


page("diary.html", "Doris's Diary", "Doris's public record of every scam she has answered, newest first.", "/diary", """
  <section class="page-head">
    <div class="shell">
      <p class="eyebrow">Public record</p>
      <h1 class="h-hero">Doris's diary</h1>
      <p class="lede">Everything she does, newest first: cases she opens, letters she writes, what scammers send back, and the links she examines. Scammer text is untrusted and shown with links made unclickable.</p>
      <div class="chain" id="chain"><span class="dot"></span><span>Checking the log chain…</span></div>
    </div>
  </section>
  <section class="section-tight rule-top" style="padding-top:40px">
    <div class="shell">
      <div class="filters" id="filters" role="group" aria-label="Filter by entry type"></div>
      <ol class="timeline" id="timeline"><li class="empty">Putting the kettle on…</li></ol>
    </div>
  </section>""")

page("case.html", "Case file · Doris", "One of Doris's cases: the scam, the letters, the evidence and the log.", "/case", """
  <section class="page-head">
    <div class="shell" id="case-root">
      <p class="eyebrow"><a href="/case" style="text-decoration:none">Case files</a></p>
      <div class="case-head"><h1 class="h-hero" id="case-title">Case file</h1><span class="status" id="case-status">Loading</span></div>
      <dl class="facts">
        <div><dt>Type</dt><dd id="f-type">…</dd></div>
        <div><dt>Opened</dt><dd id="f-opened">…</dd></div>
        <div><dt>Letters from Doris</dt><dd id="f-letters">…</dd></div>
        <div><dt>Scammer replies</dt><dd id="f-replies">…</dd></div>
      </dl>
    </div>
  </section>
  <section class="section-tight rule-top">
    <div class="shell split">
      <div>
        <p class="eyebrow">Correspondence</p>
        <h2 class="h-lg">The letters, in order.</h2>
        <p class="lede">The sender's address is withheld. Their messages are untrusted, so links are shown unclickable and personal details are removed.</p>
      </div>
      <div class="thread" id="thread"></div>
    </div>
  </section>
  <section class="section-tight rule-top">
    <div class="shell split">
      <div>
        <p class="eyebrow">Tamper-evident log</p>
        <h2 class="h-lg">Every step, chained.</h2>
        <p class="lede">Each entry carries the fingerprint of the one before it, so any edit or deletion breaks the chain.</p>
      </div>
      <table class="log"><thead><tr><th>When</th><th>Event</th><th>Hash</th></tr></thead><tbody id="log-body"></tbody></table>
    </div>
  </section>
  <section class="section-tight rule-top">
    <div class="shell" id="other-cases"></div>
  </section>""")

page("how-it-works.html", "How Doris works", "One scam's journey through Doris, where her keys live, and the tests that enforce her rules.", "/how-it-works", """
  <section class="page-head">
    <div class="shell">
      <p class="eyebrow">Method</p>
      <h1 class="h-hero">How Doris works</h1>
      <p class="lede">One scam's journey, where the keys live, and the automated tests that enforce her rules.</p>
    </div>
  </section>
  <section class="section-tight rule-top">
    <div class="shell">
      <h2 class="h-lg">One scam's journey</h2>
      <ol class="steps seven">
        <li><span class="step-n">01</span><h3>Forward</h3><p>A family forwards a suspected scam to ask-doris@agentmail.to.</p></li>
        <li><span class="step-n">02</span><h3>Judge</h3><p>Doris decides whether it is a scam and tells the family in plain words.</p></li>
        <li><span class="step-n">03</span><h3>Reply</h3><p>She writes to the scammer from her own address, never the family's.</p></li>
        <li><span class="step-n">04</span><h3>Open</h3><p>Any link is opened in a separate throwaway computer.</p></li>
        <li><span class="step-n">05</span><h3>Record</h3><p>What the page asked for, and where it really led, is recorded.</p></li>
        <li><span class="step-n">06</span><h3>Wipe</h3><p>The throwaway computer rewinds itself to a clean snapshot.</p></li>
        <li><span class="step-n">07</span><h3>Report</h3><p>Confirmed phishing pages are reported for takedown, and everything goes into the public log.</p></li>
      </ol>
    </div>
  </section>
  <section class="section rule-top">
    <div class="shell">
      <p class="eyebrow">Where the keys live</p>
      <h2 class="h-lg">Two computers, and neither holds a key.</h2>
      <div class="cols3">
        <div><h3>In a vault outside both</h3><p>Email, the AI model and storage are reached through Fly.io Sprites connectors. The keys stay in Fly; no key exists inside either computer.</p></div>
        <div><h3>Doris's home</h3><p>Reads mail, decides and writes letters. Only this computer is allowed to use her connectors.</p></div>
        <div><h3>The throwaway computer</h3><p>Opens scammers' links in a browser. Every connector refuses it, and it is wiped after every visit. If a page turns nasty, there is nothing there to steal.</p></div>
      </div>
    </div>
  </section>
  <section class="section rule-top">
    <div class="shell split">
      <div>
        <p class="eyebrow">Her rules</p>
        <h2 class="h-lg">What Doris will never do.</h2>
        <p class="lede">Each rule is code, checked by a named test that runs on every change.</p>
      </div>
      <ol class="rules">
        <li><span class="n">1</span><div><b>Never sends money, card or bank numbers.</b><span>Replies with card-like or bank account numbers are refused.</span><code class="test">tests/test_rules.py::test_outgoing_blocks</code></div></li>
        <li><span class="n">2</span><div><b>Never mentions the family.</b><span>The forwarder is stripped from the scam and can never reach the scammer or the diary.</span><code class="test">tests/test_brain.py::test_family_identity_never_reaches_scammer_or_diary</code></div></li>
        <li><span class="n">3</span><div><b>Never threatens anyone.</b><span>Threatening language blocks a reply.</span><code class="test">tests/test_rules.py::test_outgoing_blocks</code></div></li>
        <li><span class="n">4</span><div><b>Never runs anything a scammer sends.</b><span>Downloads and unsafe addresses never reach the throwaway computer.</span><code class="test">tests/test_brain.py::test_trapdoor_refuses_unsafe_links_without_calling</code></div></li>
        <li><span class="n">5</span><div><b>Types fake details only into the scam's own page.</b><span>Never into a real site the scam redirects to.</span><code class="test">tests/test_rules.py::test_may_fill_canary</code></div></li>
        <li><span class="n">6</span><div><b>Never writes to government, university or no-reply addresses.</b><span>A spoofed sender is not a reason to bother a real institution.</span><code class="test">tests/test_rules.py::test_reply_targets</code></div></li>
      </ol>
    </div>
  </section>""")
print("built diary.html, case.html, how-it-works.html")
