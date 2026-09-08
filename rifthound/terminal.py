from __future__ import annotations
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAVE=True
except Exception:
    HAVE=False
BANNER=r''' ____  _  __ _   _   _                       _
|  _ \\(_)/ _| |_| | | | ___  _   _ _ __   __| |
| |_) | | |_| __| |_| |/ _ \\| | | | '_ \\ / _` |
|  _ <| |  _| |_|  _  | (_) | |_| | | | | (_| |
|_| \\_\\_|_|  \\__|_| |_|\\___/ \\__,_|_| |_|\\__,_|'''
class UI:
    def __init__(self,quiet=False):self.quiet=quiet;self.console=Console() if HAVE else None
    def banner(self,v):
        if self.quiet:return
        msg=f'{BANNER}\nv{v} • author kdairatchi • recon → validate → correlate → chain'
        self.console.print(Panel.fit(msg,border_style='cyan',title='RiftHound')) if self.console else print(msg)
    def info(self,m):
        if not self.quiet:(self.console.print(f'[cyan]◆[/cyan] {m}') if self.console else print('[*]',m))
    def ok(self,m):
        if not self.quiet:(self.console.print(f'[green]✓[/green] {m}') if self.console else print('[+]',m))
    def warn(self,m):
        if not self.quiet:(self.console.print(f'[yellow]⚠[/yellow] {m}') if self.console else print('[!]',m))
    def phase(self,n,t,d=''):
        if self.quiet:return
        msg=f'PHASE {n}  {t}'+(f'\n{d}' if d else '')
        self.console.print(Panel(msg,border_style='blue')) if self.console else print('\n===',msg,'===')
    def findings(self,rows,limit=20):
        if self.quiet or not rows:return
        if not self.console:
            for r in rows[:limit]:print(f"[{r.get('confidence_score',0):03}] {r.get('status')} {r.get('family')} {r.get('url')}")
            return
        t=Table(title='Evidence Gates / Corroborated Signals',box=None)
        for c in ('Score','State','Family','Tools','Target'):t.add_column(c)
        for r in rows[:limit]:t.add_row(str(r.get('confidence_score',0)),r.get('status',''),r.get('family',''),','.join(r.get('tools',[])),r.get('url','')[:90])
        self.console.print(t)
