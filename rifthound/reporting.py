from pathlib import Path
import html
CSS='body{background:#070b14;color:#e7eefc;font:14px monospace;margin:0}.w{max-width:1400px;margin:auto;padding:28px}.p{background:#0d1423;border:1px solid #1f2a3d;border-radius:14px;padding:18px;margin:14px 0}.c{color:#22d3ee}.m{color:#8997ad}.tag{border:1px solid #33415b;border-radius:999px;padding:2px 7px;margin:2px;display:inline-block}.r{display:grid;grid-template-columns:60px 130px 100px 1fr;gap:12px;border-top:1px solid #1f2a3d;padding:10px}.hi{color:#34d399}.md{color:#fbbf24}'
def write_html(path,summary,evidence,chains):
 esc=lambda x:html.escape(str(x));b=[f'<html><head><meta charset=utf-8><style>{CSS}</style><title>RiftHound</title></head><body><div class=w><h1>Rift<span class=c>Hound</span></h1><div class=m>evidence-first bug bounty hunting • kdairatchi</div><div class=p><b>URLs</b> {summary.get("urls",0)} &nbsp; <b>Signals</b> {len(evidence)} &nbsp; <b>Chains</b> {len(chains)}</div><div class=p><h2 class=c>Evidence gates</h2>']
 for e in evidence[:200]:
  sc=int(e.get('confidence_score',0));cl='hi' if sc>=70 else 'md';b.append(f'<div class=r><div class={cl}>{sc}</div><div>{esc(e.get("status"))}</div><div>{esc(e.get("family"))}</div><div>{esc(e.get("url"))}<br>{" ".join("<span class=tag>"+esc(t)+"</span>" for t in e.get("tools",[]))}</div></div>')
 b.append('</div><div class=p><h2 class=c>Chain hypotheses</h2>')
 for c in chains[:150]:b.append(f'<div class=r><div>{c.get("score")}</div><div>{esc(c.get("id"))}</div><div>{esc(c.get("host"))}</div><div>{esc(c.get("title"))}</div></div>')
 b.append('</div></div></body></html>');Path(path).write_text(''.join(b))
def write_markdown(path,summary,evidence,chains):
 l=['# RiftHound Hunting Report','',f"Author: **kdairatchi**  ",f"URLs: **{summary.get('urls',0)}**  ",f"Signals: **{len(evidence)}**  ",'','> Scores are hunt-priority scores, not CVSS.','','## Evidence gates','']
 for e in evidence[:50]:l += [f"### {e.get('confidence_score',0):03} — {e.get('family')} — {e.get('status')}",f"`{e.get('url','')}`",f"Tools: {', '.join(e.get('tools',[]))}",'']
 l+=['## Chain hypotheses','']
 for c in chains[:60]:l += [f"### {c.get('score',0):03} — {c.get('id')} — {c.get('title')}",f"Host: `{c.get('host')}`",f"Signals: {', '.join(c.get('signals',[]))}",'']
 Path(path).write_text('\n'.join(l)+'\n')
