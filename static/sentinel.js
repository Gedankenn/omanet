/* SENTINELA // deteccao leve de ameaca dentro da pagina inicial do omanet.
   Consome GET /api/threats (o motor roda no app.py, junto do ARP e das portas).
   Zero animacao: painel estatico, so texto e cor. */
(function () {
  "use strict";
  var ROTULO = { critical: "CRÍTICO", warn: "ALERTA", notice: "AVISO", info: "INFO" };
  var ORDEM = ["critical", "warn", "notice", "info"];
  var aberto = false, dados = null, falhou = false;

  var CSS = `
  .omsec{margin:12px 0 0;border:1px solid var(--line,#1B2433);border-radius:10px;background:var(--panel,#0B0F18)}
  .omsec-h{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 12px;border-bottom:1px solid var(--line,#1B2433)}
  .omsec-h h2{margin:0;font:700 9.5px/1 var(--mono,monospace);letter-spacing:1.4px;color:var(--mute,#8496AC);text-transform:uppercase}
  .omsec-h h2 b{color:var(--cyan,#22E8FF)}
  .omsec-c{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-left:2px}
  .omsec-s{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line-hi,#2C3A50);border-radius:6px;
    background:var(--sunken,#0A0C14);padding:5px 8px;font:700 10px/1 var(--mono,monospace);letter-spacing:.8px}
  .omsec-s i{width:6px;height:6px;border-radius:50%;background:currentColor}
  .omsec-s.critical{color:#FF4D5E} .omsec-s.warn{color:#FFC24A} .omsec-s.notice{color:#22E8FF} .omsec-s.info{color:#8496AC}
  .omsec-s.zero{opacity:.45}
  .omsec-h .omsec-when{font:400 9.5px/1 var(--mono,monospace);letter-spacing:.8px;color:var(--mute,#8496AC)}
  .omsec-h button{margin-left:auto;min-height:30px;padding:0 10px;border-radius:6px;border:1px solid var(--line-hi,#2C3A50);
    background:var(--sunken,#0A0C14);color:var(--dim,#A9BCD2);font:700 9px/1 var(--mono,monospace);letter-spacing:1.1px;text-transform:uppercase}
  .omsec-h button:hover{color:var(--ink,#DDF6FF);border-color:var(--cyan,#22E8FF)}
  .omsec-resumo{padding:10px 12px;font:400 11px/1.5 var(--mono,monospace);color:var(--dim,#A9BCD2)}
  .omsec-resumo b{color:var(--ink,#DDF6FF)}
  .omsec-resumo .ok{color:#9CFF4A}
  .omsec-lista[hidden]{display:none}
  .omsec table{width:100%;border-collapse:collapse}
  .omsec th{font:700 8.5px/1 var(--mono,monospace);letter-spacing:1.1px;color:var(--mute,#8496AC);text-transform:uppercase;
    text-align:left;padding:8px 10px;background:var(--sunken,#0A0C14);border-bottom:1px solid var(--line,#1B2433)}
  .omsec td{padding:8px 10px;border-bottom:1px solid #121a26;font:400 11px/1.4 var(--mono,monospace);color:var(--dim,#A9BCD2);vertical-align:top}
  .omsec tr:last-child td{border-bottom:0}
  .omsec .pill{display:inline-block;border:1px solid currentColor;border-radius:4px;padding:3px 5px;
    font:700 8px/1 var(--mono,monospace);letter-spacing:.8px}
  .omsec .pill.critical{color:#FF4D5E} .omsec .pill.warn{color:#FFC24A} .omsec .pill.notice{color:#22E8FF} .omsec .pill.info{color:#8496AC}
  .omsec .regra{color:var(--ink,#DDF6FF);font-weight:700}
  .omsec .ip{color:var(--cyan,#22E8FF)}
  .omsec .num{color:var(--mute,#8496AC);white-space:nowrap}
  @media(max-width:620px){
    .omsec-h{gap:8px}
    .omsec-h button{margin-left:0;width:100%}
    .omsec .esconde{display:none}
  }`;

  function hhmm(ts) {
    try {
      return new Date(ts * 1000).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
    } catch (e) { return "—"; }
  }

  function montar() {
    var style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);

    var sec = document.createElement("section");
    sec.className = "omsec";
    sec.id = "sentinela";
    sec.setAttribute("aria-labelledby", "sentinelaH");
    sec.innerHTML =
      '<div class="omsec-h">' +
        '<h2 id="sentinelaH">SENTINELA <b>ameaças na LAN</b></h2>' +
        '<div class="omsec-c" id="omsecC"></div>' +
        '<span class="omsec-when" id="omsecWhen">—</span>' +
        '<button type="button" id="omsecBtn" aria-expanded="false" aria-controls="omsecLista">detalhes</button>' +
      '</div>' +
      '<div class="omsec-resumo" id="omsecResumo">lendo…</div>' +
      '<div class="omsec-lista" id="omsecLista" hidden></div>';

    var alvo = document.querySelector(".stats");
    if (alvo && alvo.parentNode) alvo.parentNode.insertBefore(sec, alvo.nextSibling);
    else {
      var layout = document.querySelector(".layout");
      if (layout && layout.parentNode) layout.parentNode.insertBefore(sec, layout);
      else document.body.insertBefore(sec, document.body.firstChild);
    }

    document.getElementById("omsecBtn").addEventListener("click", function () {
      aberto = !aberto;
      this.setAttribute("aria-expanded", String(aberto));
      this.textContent = aberto ? "fechar" : "detalhes";
      pintar();
    });
  }

  function pintar() {
    var cont = document.getElementById("omsecC");
    var resumo = document.getElementById("omsecResumo");
    var lista = document.getElementById("omsecLista");
    var quando = document.getElementById("omsecWhen");
    if (!cont || !resumo) return;

    if (falhou) {
      cont.innerHTML = "";
      resumo.innerHTML = '<span style="color:#FFC24A">motor de ameaças não respondeu</span>';
      lista.hidden = true;
      return;
    }
    if (!dados) return;

    var sev = dados.by_severity || {};
    cont.innerHTML = ORDEM.map(function (s) {
      var n = sev[s] || 0;
      return '<span class="omsec-s ' + s + (n ? "" : " zero") + '"><i></i>' +
             ROTULO[s] + " " + n + "</span>";
    }).join("");
    quando.textContent = dados.evaluated_at ? "avaliado " + hhmm(dados.evaluated_at) : "—";

    var total = dados.total || 0;
    var criticos = sev.critical || 0;
    var alertas = sev.warn || 0;
    if (!total) {
      resumo.innerHTML = '<span class="ok">nada fora do esperado.</span> ' +
        "MAC do gateway estável, nenhum serviço arriscado exposto, nenhum aparelho novo sem identificação.";
    } else if (!criticos && !alertas) {
      resumo.innerHTML = "<b>" + total + "</b> achado(s) de baixa gravidade — " +
        "sem crítico nem alerta agora.";
    } else {
      resumo.innerHTML = "<b>" + total + "</b> achado(s), <b>" + criticos + " crítico(s)</b> e <b>" +
        alertas + " alerta(s)</b>.";
    }

    if (!total) { lista.hidden = true; return; }
    if (!aberto) { lista.hidden = true; return; }

    var linhas = (dados.items || []).map(function (i) {
      return "<tr>" +
        '<td><span class="pill ' + i.severity + '">' + (ROTULO[i.severity] || i.severity) + "</span></td>" +
        '<td class="regra">' + i.rule + "</td>" +
        '<td class="ip num">' + (i.ip || "—") + "</td>" +
        '<td class="num">' + (i.port || "—") + "</td>" +
        '<td class="esconde">' + (i.detail || "") + "</td>" +
        '<td class="num">' + i.count + "× · " + hhmm(i.last_ts) + "</td>" +
        "</tr>";
    }).join("");
    lista.innerHTML = "<table><thead><tr><th>gravidade</th><th>regra</th><th>ip</th><th>porta</th>" +
      "<th class=\"esconde\">o que foi visto</th><th>repetições</th></tr></thead><tbody>" +
      linhas + "</tbody></table>";
    lista.hidden = false;
  }

  function carregar() {
    fetch("/api/threats", { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (j) { dados = j; falhou = false; pintar(); })
      .catch(function () { falhou = true; pintar(); });
  }

  function iniciar() {
    if (document.getElementById("sentinela")) return;
    montar();
    carregar();
    setInterval(carregar, 30000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", iniciar);
  else iniciar();
})();
