
function $(sel){return document.querySelector(sel)}
function $all(sel){return Array.from(document.querySelectorAll(sel))}

function setMode(mode){
  $('#mode').value = mode
  $all('#mode-tabs .tab-btn').forEach(btn => {
    btn.classList.toggle('selected', btn.dataset.mode === mode)
  })
  const single = $('#scenario-single')
  const help = $('#mode-help')
  if(mode === 'compare_multi'){
    single.disabled = true
    help.textContent = 'Compare‑Multi: single scenario selection is disabled. Use the checkboxes.'
  }else{
    single.disabled = false
    help.textContent = 'Single‑scenario modes use the dropdown. Checkboxes are ignored.'
  }
}

function copyText(id){
  const el = document.getElementById(id)
  if(!el) return
  navigator.clipboard.writeText(el.textContent.trim()).then(()=>{
    alert('Copied!')
  })
}

window.copyText = copyText

document.addEventListener('DOMContentLoaded', () => {
  // tabs
  $all('#mode-tabs .tab-btn').forEach(btn => {
    btn.addEventListener('click', () => setMode(btn.dataset.mode))
  })
  setMode($('#mode').value || 'analyze')

  // message counter
  const msg = $('#message'), cc = $('#char-count')
  if(msg && cc){
    const upd = ()=> cc.textContent = (msg.value||'').length + ' chars'
    msg.addEventListener('input', upd); upd()
  }

  // drag & drop
  const drop = $('#drop'), file = $('#file')
  if(drop && file){
    drop.addEventListener('click', ()=> file.click())
    ;['dragenter','dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('ring-1','ring-sky-500') }))
    ;['dragleave','drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('ring-1','ring-sky-500') }))
    drop.addEventListener('drop', e => {
      const f = e.dataTransfer.files[0]; if(f){ file.files = e.dataTransfer.files }
    })
  }

  // spinner
  const run = $('#run-btn'), spin = $('#spinner'), form = $('#cn-form')
  if(form && run && spin){
    form.addEventListener('submit', () => { spin.classList.remove('hidden') })
  }
})
