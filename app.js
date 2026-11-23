/* ScamShield AI - frontend logic.
   Talks to the Flask API. All user text is inserted with textContent / text nodes (never innerHTML). */
(() => {
  'use strict';

  // ------------------------------------------------------------ constants
  const LEVEL_TEXT = { Low: 'Low risk', Medium: 'Medium risk', High: 'High risk' };
  const HEADLINE = {
    Low: 'Koi bada khatra nahi dikha',
    Medium: 'Savdhan rahein, kuch shak wali baatein hain',
    High: 'Fraud hone ki sambhavna bahut zyada hai',
  };
  const KIND_TEXT = { sms: 'Message', combined: 'Message', url: 'Link', phone: 'Number' };
  const SCAM_TYPES = [
    'Digital Arrest / Fake Police Scam',
    'KYC / Bank Account Block Scam',
    'OTP / PIN / Password Theft',
    'Lottery / Prize Scam',
    'Fake Job / Part-time Task Scam',
    'Fake Courier / Customs Scam',
    'Electricity Bill Disconnection Scam',
    'Fake Refund / Loan / Reward Scam',
  ];
  const EXAMPLES = [
    { label: 'KYC wala message',
      text: 'Dear customer, aapka SBI account band ho jayega. Turant KYC update karein: http://sbi-kyc-update.xyz/login ya call karein 9000000002' },
    { label: 'Digital arrest call',
      text: 'Main CBI officer bol raha hun. Aapke naam par arrest warrant hai. Video call par rahiye aur kisi ko mat batana, case band karne ke liye abhi paisa transfer karein.' },
    { label: 'Asli OTP message',
      text: '123456 is your OTP for login. Do not share OTP with anyone.' },
  ];
  const TABS = ['check', 'chat', 'practice', 'history', 'report'];
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ------------------------------------------------------------ helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  /** Tiny element builder: h('div', {class:'x', onclick: fn}, child, child...) */
  function h(tag, props, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return node;
  }

  async function api(path, options = {}) {
    let res;
    try {
      res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
    } catch (_) {
      throw new Error('Server se connect nahi ho paya. Check karein ki app chal rahi hai.');
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* no body */ }
    if (!res.ok) throw new Error((data && data.error) || 'Kuch gadbad ho gayi. Dobara try karein.');
    return data;
  }
  const post = (path, body) => api(path, { method: 'POST', body: JSON.stringify(body) });

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      const ta = h('textarea', { readonly: true, style: 'position:fixed;opacity:0;top:0;left:0' });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (_) { /* ignore */ }
      ta.remove();
      return ok;
    }
  }

  const lower = (level) => String(level).toLowerCase();

  // ------------------------------------------------------------ tabs
  function showTab(name, focusTab) {
    if (!TABS.includes(name)) name = 'check';
    for (const t of TABS) {
      const on = t === name;
      const tab = $('#tab-' + t);
      tab.setAttribute('aria-selected', String(on));
      tab.tabIndex = on ? 0 : -1;
      $('#panel-' + t).hidden = !on;
    }
    if (focusTab) $('#tab-' + name).focus();
    if (location.hash !== '#' + name) window.history.replaceState(null, '', '#' + name);
    if (name === 'history') loadHistory();
    window.scrollTo(0, 0);
  }

  $$('.tab').forEach((tab) => {
    tab.addEventListener('click', () => showTab(tab.id.replace('tab-', '')));
    tab.addEventListener('keydown', (e) => {
      const i = TABS.indexOf(tab.id.replace('tab-', ''));
      let next = null;
      if (e.key === 'ArrowRight') next = TABS[(i + 1) % TABS.length];
      else if (e.key === 'ArrowLeft') next = TABS[(i - 1 + TABS.length) % TABS.length];
      else if (e.key === 'Home') next = TABS[0];
      else if (e.key === 'End') next = TABS[TABS.length - 1];
      if (next) { e.preventDefault(); showTab(next, true); }
    });
  });

  // ------------------------------------------------------------ result pieces
  function gauge(score, level) {
    return h('div', { class: 'gauge', role: 'img', 'aria-label': `Risk score ${score} out of 100, ${level}` },
      h('div', { class: 'gauge-track' },
        h('span', { class: 'zone low' }), h('span', { class: 'zone medium' }), h('span', { class: 'zone high' }),
        h('span', { class: 'gauge-pin', style: `left:${Math.max(0, Math.min(100, score))}%` })),
      h('div', { class: 'gauge-meta' }, h('strong', { text: String(score) }), ' / 100'));
  }

  function verdictCard(d, kind) {
    const hasType = d.scam_type && d.scam_type !== 'No clear scam pattern';
    const typeLabel = kind === 'phone' ? 'Report mein type: ' : 'Scam type: ';
    return h('section', { class: 'panel verdict ' + lower(d.level) },
      h('div', { class: 'verdict-top' },
        h('div', { class: 'stamp', text: LEVEL_TEXT[d.level] }),
        h('h2', { text: HEADLINE[d.level] })),
      hasType ? h('p', { class: 'scam-type' }, h('span', { text: typeLabel }), d.scam_type) : null,
      d.explanation ? h('p', { class: 'explain', text: d.explanation }) : null,
      gauge(d.score, d.level));
  }

  function panel(title, hint, ...children) {
    return h('section', { class: 'panel' },
      h('h3', { text: title }),
      hint ? h('p', { class: 'hint', text: hint }) : null,
      children);
  }

  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  /** Highlight phrases inside the user's own text (case-insensitive, whitespace tolerant). */
  function highlighted(text, phrases) {
    const ranges = [];
    for (const p of phrases) {
      const t = (p || '').trim();
      if (t.length < 2) continue;
      const body = t.split(/\s+/).map(escapeRe).join('\\s+');
      const pre = /^[A-Za-z0-9]/.test(t) ? '(?<![A-Za-z0-9])' : '';
      const post = /[A-Za-z0-9]$/.test(t) ? '(?![A-Za-z0-9])' : '';
      let re;
      try { re = new RegExp(pre + body + post, 'gi'); } catch (_) { continue; }
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        ranges.push([m.index, m.index + m[0].length]);
      }
    }
    ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
    const merged = [];
    for (const r of ranges) {
      const last = merged[merged.length - 1];
      if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
      else merged.push([r[0], r[1]]);
    }
    const parts = [];
    let pos = 0;
    for (const [s, e] of merged) {
      if (s > pos) parts.push(text.slice(pos, s));
      parts.push(h('mark', { text: text.slice(s, e) }));
      pos = e;
    }
    if (pos < text.length) parts.push(text.slice(pos));
    return h('p', { class: 'message-view' }, parts);
  }

  function breakdown(b) {
    const item = (label, val) => h('div', {}, h('dt', { text: label }), h('dd', { text: String(val) }));
    return panel('Score kaise bana', 'Final score in sab ko jodkar banta hai (max 100).',
      h('dl', { class: 'breakdown' },
        item('Message', b.message), item('Links', b.links), item('Numbers', b.numbers), item('Extra', b.bonus)));
  }

  function reasonsPanel(triggers, title) {
    const bad = triggers.filter((t) => t.points > 0);
    const good = triggers.filter((t) => t.points === 0);
    const kids = [];
    if (bad.length) {
      kids.push(h('ul', { class: 'reasons' }, bad.map((t) =>
        h('li', {},
          h('div', { class: 'reason-head' },
            h('code', { class: 'matched', text: t.matched }),
            h('span', { class: 'pts', text: '+' + t.points })),
          h('p', { text: t.why })))));
    } else {
      kids.push(h('p', { class: 'hint', text: 'Koi shak wala pattern nahi mila.' }));
    }
    good.forEach((t) => kids.push(h('p', { class: 'good' }, h('span', { class: 'badge low', text: 'Achha sign' }), ' ', t.why)));
    return panel(title || 'Jaanch ka vivaran', 'Har pattern ke saath dikhaye gaye points score mein jode gaye.', kids);
  }

  function advicePanel(list) {
    if (!list || !list.length) return null;
    return panel('Ab kya karein', null, h('ul', { class: 'advice' }, list.map((a) => h('li', { text: a }))));
  }

  function reportControl(number, scamType) {
    const status = h('p', { class: 'inline-status', role: 'status', hidden: true });
    const btn = h('button', { type: 'button', class: 'btn ghost small' }, 'Is number ko report karein');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      status.hidden = false;
      status.classList.remove('is-error');
      try {
        const r = await post('/api/report', { number, scam_type: scamType || 'Unknown' });
        status.textContent = `${r.message} Ab tak ${r.total_reports} report.`;
        btn.textContent = 'Report ho gaya';
      } catch (err) {
        status.textContent = err.message;
        status.classList.add('is-error');
        btn.disabled = false;
      }
    });
    return h('div', {}, btn, status);
  }

  function subResult(r, kind, scamType) {
    return h('details', { class: 'sub' },
      h('summary', {},
        h('span', { class: 'badge ' + lower(r.level), text: r.level }),
        h('span', { class: 'sub-name', text: r.input }),
        h('span', { class: 'sub-score', text: `${r.score}/100` })),
      h('div', { class: 'sub-body' },
        r.explanation ? h('p', { text: r.explanation }) : null,
        r.triggers.some((t) => t.points > 0) || r.triggers.length ? reasonsList(r.triggers) : null,
        kind === 'phone' ? reportControl(r.normalized, scamType) : null));
  }

  function reasonsList(triggers) {
    const bad = triggers.filter((t) => t.points > 0);
    const good = triggers.filter((t) => t.points === 0);
    return h('div', {},
      bad.length ? h('ul', { class: 'reasons' }, bad.map((t) =>
        h('li', {},
          h('div', { class: 'reason-head' }, h('code', { class: 'matched', text: t.matched }), h('span', { class: 'pts', text: '+' + t.points })),
          h('p', { text: t.why })))) : null,
      good.map((t) => h('p', { class: 'good' }, h('span', { class: 'badge low', text: 'Achha sign' }), ' ', t.why)));
  }

  function familyAlert(text) {
    if (!text) return null;
    const status = h('span', { class: 'sr-only', role: 'status' });
    const copyBtn = h('button', { type: 'button', class: 'btn ghost' }, 'Copy karein');
    copyBtn.addEventListener('click', async () => {
      const ok = await copyText(text);
      copyBtn.textContent = ok ? 'Copy ho gaya' : 'Copy nahi hua';
      status.textContent = copyBtn.textContent;
      setTimeout(() => { copyBtn.textContent = 'Copy karein'; }, 2000);
    });
    return panel('Parivar ko alert bhejein', 'Ye message WhatsApp par bhejkar apno ko is scam se bachayein.',
      h('pre', { class: 'alert-text', text }),
      h('div', { class: 'actions' },
        copyBtn,
        h('a', { class: 'btn primary', href: 'https://wa.me/?text=' + encodeURIComponent(text),
                 target: '_blank', rel: 'noopener noreferrer' }, 'WhatsApp par bhejein'),
        status));
  }

  // ------------------------------------------------------------ result renderers
  function renderCombined(d, text) {
    const phrases = [
      ...d.sms.triggers.filter((t) => t.points > 0).map((t) => t.matched),
      ...d.urls.map((u) => u.input),
      ...d.phones.map((p) => p.input),
    ];
    const out = [
      verdictCard(d, 'sms'),
      panel('Aapka message', 'Shak wale hisse highlight kiye gaye hain.', highlighted(text, phrases)),
      breakdown(d.breakdown),
      reasonsPanel(d.sms.triggers, 'Message ki jaanch'),
    ];
    if (d.urls.length) {
      out.push(panel(`Message mein mile links (${d.urls.length})`, 'Kholkar dekhein ki har link kyun flag hua.',
        h('div', { class: 'subs' }, d.urls.map((u) => subResult(u, 'url')))));
    }
    if (d.phones.length) {
      out.push(panel(`Message mein mile numbers (${d.phones.length})`, null,
        h('div', { class: 'subs' }, d.phones.map((p) => subResult(p, 'phone', d.scam_type)))));
    }
    out.push(advicePanel(d.advice), familyAlert(d.family_alert));
    return out.filter(Boolean);
  }

  function renderUrl(d) {
    return [
      verdictCard(d, 'url'),
      panel('Link', null, h('p', { class: 'message-view', text: d.input })),
      reasonsPanel(d.triggers, 'Link ki jaanch'),
      advicePanel(d.advice),
    ];
  }

  function renderPhone(d) {
    const reports = d.reports > 0 ? `${d.reports} baar report hua hai.` : 'Local database mein is number ki koi report nahi hai.';
    return [
      verdictCard(d, 'phone'),
      panel('Number', null,
        h('p', { class: 'message-view', text: d.normalized || d.input }),
        h('p', { class: 'hint', text: reports })),
      reasonsPanel(d.triggers, 'Number ki jaanch'),
      advicePanel(d.advice),
      panel('Aapko is number se scam call/SMS aaya?', 'Report karne se dusre log bhi is number se bach sakte hain.',
        reportControl(d.normalized, d.scam_type)),
    ];
  }

  // ------------------------------------------------------------ CHECK tab
  const checkForm = $('#check-form');
  const inputs = { message: $('#in-message'), url: $('#in-url'), phone: $('#in-phone') };
  const results = $('#results');
  const checkError = $('#check-error');
  const checkBtn = $('#check-btn');
  const EMPTY_MSG = {
    message: 'Pehle koi SMS ya message paste karein.',
    url: 'Check karne ke liye link daalein.',
    phone: 'Check karne ke liye number daalein.',
  };

  const currentMode = () => $('input[name="mode"]:checked', checkForm).value;

  function setMode(mode) {
    const radio = $(`input[name="mode"][value="${mode}"]`, checkForm);
    radio.checked = true;
    $$('.field-group', checkForm).forEach((g) => { g.hidden = g.dataset.mode !== mode; });
    checkError.hidden = true;
    results.replaceChildren();
  }

  $$('input[name="mode"]', checkForm).forEach((r) => r.addEventListener('change', () => setMode(r.value)));
  Object.values(inputs).forEach((el) => el.addEventListener('input', () => { checkError.hidden = true; }));

  const exampleBox = $('#examples');
  EXAMPLES.forEach((ex) => exampleBox.append(h('button', {
    type: 'button', class: 'chip', text: ex.label,
    onclick: () => { inputs.message.value = ex.text; checkError.hidden = true; inputs.message.focus(); },
  })));

  function showResult(nodes) {
    results.replaceChildren(...nodes);
    results.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    results.focus({ preventScroll: true });
  }

  function showCheckError(msg) {
    checkError.textContent = msg;
    checkError.hidden = false;
  }

  checkForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const mode = currentMode();
    const value = inputs[mode].value.trim();
    if (!value) { showCheckError(EMPTY_MSG[mode]); inputs[mode].focus(); return; }

    checkError.hidden = true;
    checkBtn.disabled = true;
    checkBtn.textContent = 'Check ho raha hai...';
    try {
      if (mode === 'message') showResult(renderCombined(await post('/api/check/combined', { text: value }), value));
      else if (mode === 'url') showResult(renderUrl(await post('/api/check/url', { url: value })));
      else showResult(renderPhone(await post('/api/check/phone', { number: value })));
    } catch (err) {
      showCheckError(err.message);
    } finally {
      checkBtn.disabled = false;
      checkBtn.textContent = 'Check karein';
    }
  });

  // ------------------------------------------------------------ CHAT tab
  const chatLog = $('#chat-log');
  const chatForm = $('#chat-form');
  const chatInput = $('#chat-input');
  const SUGGESTIONS = ['OTP kya hai?', 'Digital arrest kya hota hai?', 'Fraud report kahan karein?', 'Scam se kaise bachein?'];

  function scrollChat() {
    const last = chatLog.lastElementChild;
    if (last) last.scrollIntoView({ block: 'nearest', behavior: reduceMotion ? 'auto' : 'smooth' });
  }

  function addUser(text) {
    chatLog.append(h('div', { class: 'bubble user', text }));
    scrollChat();
  }

  function suggestionButtons(list) {
    if (!list || !list.length) return null;
    return h('div', { class: 'bubble-extra' }, list.map((s) =>
      h('button', { type: 'button', class: 'chip', text: s, onclick: () => sendChat(s) })));
  }

  function addBot(reply, extra) {
    const bubble = h('div', { class: 'bubble bot' });
    if (extra && extra.analysis) {
      bubble.append(h('span', { class: 'badge ' + lower(extra.analysis.level), text: LEVEL_TEXT[extra.analysis.level] }), h('br'));
    }
    bubble.append(document.createTextNode(reply));
    if (extra && extra.analysis) {
      bubble.append(h('div', { class: 'bubble-extra' },
        h('button', { type: 'button', class: 'btn ghost small', onclick: () => openInCheck(extra.original, extra.analysis) },
          'Poora result dekhein')));
    }
    if (extra && extra.suggestions) { const s = suggestionButtons(extra.suggestions); if (s) bubble.append(s); }
    chatLog.append(bubble);
    scrollChat();
  }

  function openInCheck(text, analysis) {
    showTab('check');
    setMode('message');
    inputs.message.value = text;
    showResult(renderCombined(analysis, text));
  }

  async function sendChat(text) {
    const msg = (text || '').trim();
    if (!msg) return;
    addUser(msg);
    chatInput.value = '';
    chatInput.style.height = 'auto';
    const wait = h('div', { class: 'bubble bot wait', text: 'Soch raha hun...' });
    chatLog.append(wait);
    scrollChat();
    try {
      const data = await post('/api/chat', { message: msg });
      wait.remove();
      addBot(data.reply, { analysis: data.analysis, original: msg, suggestions: data.suggestions });
    } catch (err) {
      wait.remove();
      addBot(err.message);
    }
  }

  chatForm.addEventListener('submit', (e) => { e.preventDefault(); sendChat(chatInput.value); });
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(chatInput.value); }
  });
  chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 140) + 'px';
  });

  addBot('Namaste! Main ScamShield Helper hun. Koi SMS, link ya number paste karein, ya scam ke baare mein kuch bhi poochein.',
    { suggestions: SUGGESTIONS });

  // ------------------------------------------------------------ PRACTICE tab
  const practiceView = $('#practice-view');
  let sim = null; // { id, answers: [] }

  function errorBox(msg, retry) {
    return h('div', { class: 'empty' },
      h('p', { text: msg }),
      retry ? h('button', { type: 'button', class: 'btn ghost', onclick: retry }, 'Dobara try karein') : null);
  }

  async function loadScenarios() {
    sim = null;
    try {
      const list = await api('/api/simulator/scenarios');
      practiceView.replaceChildren(
        h('p', { class: 'hint lead', text: 'Ek nakli scammer aapse baat karega. Har step par jawab chunein, end mein score aur galtiyan dikhengi.' }),
        h('ul', { class: 'scenario-list' }, list.map((s) =>
          h('li', {}, h('button', { type: 'button', class: 'scenario-btn', onclick: () => startScenario(s.id) },
            h('strong', { text: s.title }),
            h('span', { text: s.intro }),
            h('span', { text: `${s.steps} sawaal` }))))));
    } catch (err) {
      practiceView.replaceChildren(errorBox(err.message, loadScenarios));
    }
  }

  async function startScenario(id) {
    try {
      const data = await post('/api/simulator/start', { scenario: id });
      sim = { id, answers: [] };
      renderStep(data.first, data.intro);
    } catch (err) {
      practiceView.replaceChildren(errorBox(err.message, loadScenarios));
    }
  }

  function renderStep(step, intro) {
    const feedbackSlot = h('div', { 'aria-live': 'polite' });
    const optionButtons = step.options.map((o) =>
      h('button', { type: 'button', class: 'option', text: o.text, onclick: (e) => choose(step, o.id, e.currentTarget, optionButtons, feedbackSlot) }));
    const heading = h('h3', { text: step.title, tabindex: '-1' });

    practiceView.replaceChildren(h('div', { class: 'sim' },
      h('div', { class: 'sim-head' }, heading, h('span', { text: `Sawaal ${step.step + 1} / ${step.total}` })),
      h('progress', { max: String(step.total), value: String(step.step), 'aria-label': 'Progress' }),
      intro ? h('p', { class: 'sim-intro', text: intro }) : null,
      h('div', { class: 'caller' }, h('small', { text: 'Unknown caller' }), step.scammer),
      h('p', { class: 'hint', text: 'Aap kya jawab denge?' }),
      h('ul', { class: 'options' }, optionButtons.map((b) => h('li', {}, b))),
      feedbackSlot));
    heading.focus({ preventScroll: true });
  }

  const RISK_CLASS = ['safe', 'risky', 'bad'];
  const RISK_LABEL = ['Sahi jawab', 'Risky jawab', 'Aap phas gaye'];

  async function choose(step, optionId, btn, allButtons, feedbackSlot) {
    allButtons.forEach((b) => { b.disabled = true; });
    try {
      const res = await post('/api/simulator/answer', {
        scenario: sim.id, step: step.step, option: optionId, answers: sim.answers,
      });
      sim.answers.push(optionId);
      btn.classList.add('chosen', RISK_CLASS[res.risk]);
      const nextBtn = h('button', { type: 'button', class: 'btn primary',
        onclick: () => (res.finished ? renderSummary(res.summary) : renderStep(res.next)) },
        res.finished ? 'Result dekhein' : 'Agla step');
      feedbackSlot.replaceChildren(h('div', { class: 'feedback ' + RISK_CLASS[res.risk] },
        h('div', {}, h('strong', { text: RISK_LABEL[res.risk] }), res.feedback), nextBtn));
      nextBtn.focus();
    } catch (err) {
      allButtons.forEach((b) => { b.disabled = false; });
      feedbackSlot.replaceChildren(h('p', { class: 'error', text: err.message }));
    }
  }

  function renderSummary(s) {
    const band = s.score >= 85 ? 'low' : s.score >= 50 ? 'medium' : 'high';
    const label = s.score >= 85 ? 'Scam-proof' : s.score >= 50 ? 'Thoda savdhan' : 'Khatra';
    const id = sim.id;
    const heading = h('h2', { text: s.verdict, tabindex: '-1' });
    practiceView.replaceChildren(h('div', { class: 'sim' },
      h('section', { class: 'panel verdict ' + band },
        h('div', { class: 'verdict-top' }, h('div', { class: 'stamp', text: label }), heading),
        h('p', { class: 'score-line' }, 'Aapka score: ', h('b', { text: String(s.score) }), ' / 100'),
        h('p', { class: 'explain', text: s.tip })),
      s.fell_for.length
        ? panel('Kahan phas sakte the', 'Har step par scammer ne kya kaha aur behtar jawab kya tha.',
            h('ul', { class: 'fell' }, s.fell_for.map((f) =>
              h('li', {},
                h('span', {}, h('span', { class: 'k', text: 'Scammer: ' }), f.scammer_said),
                h('span', {}, h('span', { class: 'k', text: 'Aapne chuna: ' }), f.you_chose),
                h('span', {}, h('span', { class: 'k', text: 'Problem: ' }), f.problem),
                h('span', {}, h('span', { class: 'k', text: 'Behtar jawab: ' }), f.better_reply)))))
        : panel('Shabash', null, h('p', { text: 'Aap kisi bhi step par scammer ke jaal mein nahi phanse.' })),
      h('div', { class: 'actions' },
        h('button', { type: 'button', class: 'btn primary', onclick: () => startScenario(id) }, 'Dobara khelein'),
        h('button', { type: 'button', class: 'btn ghost', onclick: loadScenarios }, 'Doosra scenario'))));
    heading.focus({ preventScroll: true });
  }

  loadScenarios();

  // ------------------------------------------------------------ HISTORY tab
  const historyList = $('#history-list');
  const historyActions = $('#history-actions');

  function formatTime(s) {
    const d = new Date(String(s).replace(' ', 'T'));
    if (isNaN(d)) return s;
    return d.toLocaleString('en-IN', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  }

  function recheck(row) {
    const mode = row.kind === 'url' ? 'url' : row.kind === 'phone' ? 'phone' : 'message';
    showTab('check');
    setMode(mode);
    inputs[mode].value = row.input_text;
    inputs[mode].focus();
  }

  function renderClearControl() {
    const ask = h('button', { type: 'button', class: 'btn ghost small' }, 'History saaf karein');
    ask.addEventListener('click', () => {
      historyActions.replaceChildren(
        h('button', { type: 'button', class: 'btn primary small', onclick: async () => {
          try { await api('/api/history', { method: 'DELETE' }); } catch (_) { /* shown on reload */ }
          loadHistory();
        } }, 'Haan, saaf karein'),
        ' ',
        h('button', { type: 'button', class: 'btn ghost small', onclick: renderClearControl }, 'Rehne dein'));
    });
    historyActions.replaceChildren(ask);
  }

  async function loadHistory() {
    try {
      const rows = await api('/api/history');
      if (!rows.length) {
        historyActions.replaceChildren();
        historyList.replaceChildren(h('div', { class: 'empty' },
          h('p', { text: 'Abhi tak koi check nahi hua. Koi message, link ya number check karenge to yahan dikhega.' }),
          h('button', { type: 'button', class: 'btn primary', onclick: () => showTab('check') }, 'Check shuru karein')));
        return;
      }
      renderClearControl();
      historyList.replaceChildren(h('ul', { class: 'history' }, rows.map((r) =>
        h('li', {},
          h('div', { class: 'history-top' },
            h('span', { class: 'badge neutral', text: KIND_TEXT[r.kind] || r.kind }),
            h('span', { class: 'badge ' + lower(r.level), text: `${r.level} ${r.score}/100` }),
            h('time', { text: formatTime(r.created_at) })),
          h('p', { class: 'history-text', text: r.input_text }),
          r.scam_type && r.scam_type !== 'No clear scam pattern' ? h('p', { class: 'history-meta', text: r.scam_type }) : null,
          h('div', {}, h('button', { type: 'button', class: 'btn ghost small', onclick: () => recheck(r) }, 'Dobara check karein'))))));
    } catch (err) {
      historyList.replaceChildren(errorBox(err.message, loadHistory));
    }
  }

  // ------------------------------------------------------------ REPORT tab
  const reportForm = $('#report-form');
  const repNumber = $('#rep-number');
  const repType = $('#rep-type');
  const repStatus = $('#report-status');
  repType.append(h('option', { value: 'Unknown', text: 'Pata nahi / Other' }));
  SCAM_TYPES.forEach((t) => repType.append(h('option', { value: t, text: t })));

  function setReportStatus(msg, isError) {
    repStatus.textContent = msg;
    repStatus.classList.toggle('is-error', !!isError);
    repStatus.hidden = false;
  }

  reportForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const number = repNumber.value.trim();
    if (!number) { setReportStatus('Pehle phone number daalein.', true); repNumber.focus(); return; }
    try {
      const r = await post('/api/report', { number, scam_type: repType.value });
      setReportStatus(`${r.message} ${r.number} ki ab tak ${r.total_reports} report hain.`, false);
      repNumber.value = '';
    } catch (err) {
      setReportStatus(err.message, true);
    }
  });

  // ------------------------------------------------------------ start
  showTab((location.hash || '#check').slice(1));
})();
