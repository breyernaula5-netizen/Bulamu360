/* Bulamu360 PDF export: turns any Bulamu360 HTML document into a real, paginated A4 PDF in the browser.
   Uses jsPDF + html2canvas (loaded from cdnjs on demand). Blocks such as day cards, table rows and
   sections are kept whole across page breaks. Exposes window.B360PDF.fromHtml(html, filename). */
(function(){
'use strict';
if (window.B360PDF) return;
var CDN = {
  jspdf:'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
  h2c:'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js'
};
function load(src){ return new Promise(function(res, rej){ var s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = function(){ rej(new Error('Could not load the PDF tools. Check your internet connection and try again.')); }; document.head.appendChild(s); }); }
function ready(){
  var p = [];
  if (!(window.jspdf && window.jspdf.jsPDF)) p.push(load(CDN.jspdf));
  if (!window.html2canvas) p.push(load(CDN.h2c));
  return Promise.all(p);
}
/* Small progress overlay */
function overlay(){
  var o = document.createElement('div');
  o.setAttribute('role', 'status');
  o.style.cssText = 'position:fixed;inset:0;z-index:2147483000;background:rgba(18,40,28,.55);display:flex;align-items:center;justify-content:center;font-family:Outfit,Arial,sans-serif;backdrop-filter:blur(3px)';
  o.innerHTML = '<div style="background:#fff;border-radius:22px;padding:26px 30px;min-width:260px;text-align:center;box-shadow:0 30px 80px rgba(0,0,0,.3)">' +
    '<div style="width:46px;height:46px;border-radius:50%;border:4px solid #d9f0e1;border-top-color:#17693f;margin:0 auto 14px;animation:b3pdfspin .9s linear infinite"></div>' +
    '<div style="font-weight:600;color:#123524;font-size:17px">Preparing your PDF</div><div data-msg style="color:#5f6f66;font-size:14px;margin-top:4px">Laying out pages…</div></div>' +
    '<style>@keyframes b3pdfspin{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){[style*=b3pdfspin]{animation:none!important}}</style>';
  document.body.appendChild(o);
  return { set:function(t){ var m = o.querySelector('[data-msg]'); if (m) m.textContent = t; }, close:function(){ o.remove(); } };
}
var PAGE_W = 794, PAGE_H = Math.round(794 * 297 / 210), MARGIN = 40, USABLE = PAGE_H - MARGIN * 2;
var KEEP = '.day,.day-block,.meal-card,.week-card,.sec,.card,.tcard,.box,.panel,.avoid-break,tr,h1,h2,h3,h4,figure,.row,.item,li,p,.cover,.hdr,.pdf-block';
function paginate(doc){
  var body = doc.body, bodyTop = body.getBoundingClientRect().top;
  var els = Array.prototype.slice.call(body.querySelectorAll(KEEP));
  // Keep only the outermost "keep" blocks that fit on one page.
  els = els.filter(function(el){ var r = el.getBoundingClientRect(); if (r.height <= 0 || r.height > USABLE * 0.92) return false; var p = el.parentElement; while (p && p !== body) { if (p.matches(KEEP) && p.getBoundingClientRect().height <= USABLE * 0.92) return false; p = p.parentElement; } return true; });
  els.forEach(function(el){
    var r = el.getBoundingClientRect(), top = r.top - bodyTop, bottom = top + r.height;
    var page = Math.floor(top / USABLE), endPage = Math.floor((bottom - 1) / USABLE);
    var isHeading = /^H[1-4]$/.test(el.tagName);
    var nearEnd = isHeading && (USABLE - (top - page * USABLE)) < 90;
    if (endPage > page || nearEnd) {
      var push = (page + 1) * USABLE - top;
      if (el.tagName === 'TR') { var td = el.firstElementChild; el.style.height = ''; Array.prototype.forEach.call(el.children, function(c){ c.style.paddingTop = (parseFloat(getComputedStyle(c).paddingTop) + push) + 'px'; }); }
      else { var sp = doc.createElement('div'); sp.style.height = push + 'px'; sp.setAttribute('data-pdf-spacer', ''); el.parentNode.insertBefore(sp, el); }
      bodyTop = body.getBoundingClientRect().top;
    }
  });
  return Math.max(1, Math.ceil((body.scrollHeight) / USABLE));
}
function fromHtml(html, filename, opts){
  opts = opts || {};
  var ui = overlay();
  var frame = document.createElement('iframe');
  frame.setAttribute('aria-hidden', 'true');
  frame.style.cssText = 'position:fixed;left:-12000px;top:0;width:' + PAGE_W + 'px;height:' + PAGE_H + 'px;border:0;background:#fff';
  document.body.appendChild(frame);
  var cleanup = function(){ frame.remove(); ui.close(); };
  var clean = String(html).replace(/<script[\s\S]*?<\/script>/gi, '');
  return ready().then(function(){
    return new Promise(function(res){ frame.onload = res; frame.srcdoc = clean; setTimeout(res, 6000); });
  }).then(function(){
    var doc = frame.contentDocument;
    var st = doc.createElement('style');
    st.textContent = 'html,body{background:#fff!important;margin:0!important;max-width:none!important;width:' + PAGE_W + 'px!important}body{padding:0 ' + (opts.sidePad == null ? 36 : opts.sidePad) + 'px!important;box-sizing:border-box}' +
      'button,.prtbtn,.no-print,[data-no-pdf],.print-bar,.toolbar{display:none!important}*{animation:none!important;transition:none!important}' +
      '.page{box-shadow:none!important;margin:0!important;max-width:none!important}';
    doc.head.appendChild(st);
    var imgs = Array.prototype.slice.call(doc.images).map(function(i){ return i.complete ? null : new Promise(function(r){ i.onload = i.onerror = r; }); }).filter(Boolean);
    return Promise.all([doc.fonts ? doc.fonts.ready : null].concat(imgs)).catch(function(){}).then(function(){ return new Promise(function(r){ setTimeout(r, 150); }); }).then(function(){ return doc; });
  }).then(function(doc){
    ui.set('Arranging pages…');
    frame.style.height = doc.body.scrollHeight + 'px';
    var pages = paginate(doc);
    frame.style.height = doc.body.scrollHeight + 'px';
    var J = window.jspdf.jsPDF, pdf = new J({ unit:'pt', format:'a4', compress:true }), pw = pdf.internal.pageSize.getWidth(), ph = pdf.internal.pageSize.getHeight();
    var scaleToPt = pw / PAGE_W, full = doc.body.scrollHeight;
    var n = Math.max(1, Math.ceil(full / USABLE));
    // Render several pages per html2canvas pass (keeps canvases under browser limits), then slice.
    var SCALE = 1.8, perChunk = Math.max(1, Math.floor(16000 / (USABLE * SCALE)));
    var chain = Promise.resolve();
    for (var c0 = 0; c0 < n; c0 += perChunk) (function(c0){
      chain = chain.then(function(){
        var c1 = Math.min(n, c0 + perChunk), y0 = c0 * USABLE, hh = Math.min(full, c1 * USABLE) - y0;
        ui.set('Pages ' + (c0 + 1) + (c1 > c0 + 1 ? '–' + c1 : '') + ' of ' + n);
        return window.html2canvas(doc.body, { scale:SCALE, useCORS:true, backgroundColor:'#ffffff', x:0, y:y0, width:PAGE_W, height:hh, windowWidth:PAGE_W, windowHeight:full, logging:false }).then(function(big){
          for (var i = c0; i < c1; i++) {
            var h = Math.min(USABLE, full - i * USABLE), part = document.createElement('canvas');
            part.width = big.width; part.height = Math.round(h * SCALE);
            part.getContext('2d').drawImage(big, 0, Math.round((i - c0) * USABLE * SCALE), big.width, part.height, 0, 0, big.width, part.height);
            if (i > 0) pdf.addPage();
            pdf.addImage(part.toDataURL('image/jpeg', 0.9), 'JPEG', 0, MARGIN * scaleToPt, pw, h * scaleToPt, undefined, 'FAST');
            pdf.setFontSize(8); pdf.setTextColor(107, 129, 118);
            pdf.text('Bulamu360 · Eat better, live better', 28, ph - 16);
            pdf.text('Page ' + (i + 1) + ' of ' + n, pw - 28, ph - 16, { align:'right' });
          }
        });
      });
    })(c0);
    return chain.then(function(){ pdf.save(filename || 'Bulamu360.pdf'); cleanup(); return true; });
  }).catch(function(err){ cleanup(); throw err; });
}
window.B360PDF = { fromHtml:fromHtml, ready:ready };
})();
