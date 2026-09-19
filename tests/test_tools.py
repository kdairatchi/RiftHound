from rifthound import tools
from rifthound.pipeline import Pipeline
from rifthound.correlation import nmap_services, nmap_vulnerability_candidates, metasploit_query, searchsploit_results
from rifthound.evidence import parse_gf_leads, parse_jsattack, parse_arjun
from rifthound.core_engine import Engine
from rifthound.reporting import write_html
from rifthound.reconner import import_artifacts


def test_httpx_collision_is_not_ready(monkeypatch):
    monkeypatch.setattr(tools, 'which_tool', lambda _: '/usr/bin/httpx')
    monkeypatch.setattr(tools, 'help_blob', lambda _: 'HTTPX command line client')

    info=tools.inspect_tool('httpx')

    assert not info.ready
    assert 'collision' in info.note


def test_silent_pipeline_tool_is_present_but_unverified(monkeypatch):
    monkeypatch.setattr(tools, 'which_tool', lambda _: '/usr/bin/kxss')
    monkeypatch.setattr(tools, 'help_blob', lambda _: '')

    info=tools.inspect_tool('kxss')

    assert info.ready
    assert 'presence only' in info.note


def test_doctor_reports_core_health(monkeypatch):
    monkeypatch.setattr(
        tools,
        'inspect_tool',
        lambda name: tools.ToolInfo(name, '/bin/tool', name != 'amass'),
    )

    report=tools.doctor()

    assert report['ready_core']==len(tools.CORE)-1
    assert report['missing_core']==['amass']
    assert not report['healthy']


def test_phase_two_wires_fallparams_to_scoped_url_list(monkeypatch, tmp_path):
    class QuietUI:
        def phase(self, *_): pass
        def warn(self, *_): pass

    cfg={
        'project': {'output_dir': str(tmp_path)},
        'scope': {'roots': ['example.com'], 'include_hosts': [], 'exclude_hosts': [], 'exclude_regex': []},
        'http': {'headers': [], 'proxy': '', 'timeout': 1, 'threads': 1, 'rps': 0, 'verify_tls': False},
    }
    pipeline=Pipeline(cfg, QuietUI(), dry_run=True)
    pipeline.urls=['https://app.example.com/search?q=one']
    pipeline.write_lines(pipeline.art/'urls.txt', pipeline.urls)
    monkeypatch.setattr('rifthound.pipeline.which_tool', lambda name: '/usr/bin/fallparams' if name == 'fallparams' else None)
    calls=[]
    monkeypatch.setattr(pipeline, 'run_cmd', lambda name, cmd, **_: calls.append((name, cmd)) or (0, '', ''))
    monkeypatch.setattr(pipeline, 'native', lambda *_: None)

    pipeline.phase2()

    name, command=next(call for call in calls if call[0] == 'fallparams')
    assert name == 'fallparams'
    assert command == ['/usr/bin/fallparams', '-u', str(pipeline.art/'urls.txt'), '-o', str(pipeline.art/'fallparams.txt'), '-silent', '-duc']


def test_bbot_results_keep_only_authorized_hosts(tmp_path):
    class QuietUI: pass

    cfg={'project': {'output_dir': str(tmp_path/'out')}, 'scope': {'roots': ['example.com'], 'include_hosts': [], 'exclude_hosts': [], 'exclude_regex': []}}
    pipeline=Pipeline(cfg, QuietUI(), dry_run=True)
    output=tmp_path/'bbot'; output.mkdir()
    (output/'output.json').write_text('[{"data": "api.example.com"}, {"data": {"url": "https://app.example.com/a"}}, {"data": "evil.invalid"}]')

    hosts, urls=pipeline.bbot_results(output)

    assert hosts == {'api.example.com', 'app.example.com'}
    assert urls == {'https://app.example.com/a'}


def test_version_correlation_parsers(tmp_path):
    report=tmp_path/'nmap.xml'
    report.write_text('<nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port></ports></host></nmaprun>')
    services=nmap_services(report)
    assert services[0]['label']=='nginx 1.24.0'
    assert metasploit_query(services[0])=='nginx 1.24.0'
    assert searchsploit_results('{"RESULTS_EXPLOIT":[{"EDB-ID":"1","Title":"Example","Path":"x"}]}')[0]['edb_id']=='1'


def test_nmap_vulnerability_candidates_are_not_validated(tmp_path):
    report=tmp_path/'vuln.xml'
    report.write_text('<nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports><port portid="443"><script id="http-vuln-cve2021" output="Possible CVE-2021-12345"/></port></ports></host></nmaprun>')
    candidate=nmap_vulnerability_candidates(report)[0]
    assert candidate['confidence']=='candidate'
    assert candidate['cves']==['CVE-2021-12345']


def test_phase_two_wires_jsattack_to_scoped_urls(monkeypatch, tmp_path):
    class QuietUI:
        def phase(self, *_): pass
        def warn(self, *_): pass

    cfg={'project': {'output_dir': str(tmp_path)}, 'scope': {'roots': ['example.com'], 'include_hosts': [], 'exclude_hosts': [], 'exclude_regex': []}, 'recon': {'jsattack': {'enabled': True}}, 'http': {'headers': [], 'proxy': '', 'timeout': 15, 'threads': 3, 'rps': 2, 'verify_tls': False}}
    pipeline=Pipeline(cfg, QuietUI(), dry_run=True);pipeline.urls=['https://app.example.com/app.js'];pipeline.write_lines(pipeline.art/'urls.txt',pipeline.urls)
    monkeypatch.setattr('rifthound.pipeline.which_tool',lambda name:'/usr/bin/jsattack' if name=='jsattack' else None)
    calls=[];monkeypatch.setattr(pipeline,'run_cmd',lambda name,cmd,**_:calls.append((name,cmd)) or (0,'',''));monkeypatch.setattr(pipeline,'native',lambda *_:None)
    pipeline.phase2()
    assert next(cmd for name,cmd in calls if name=='jsattack')==['/usr/bin/jsattack','analyze','--list',str(pipeline.art/'urls.txt'),'--depth','0','--out',str(pipeline.art/'jsattack'),'--threads','3','--rate','2','--timeout','15','--silent']


def test_gf_xss_candidates_feed_kxss(monkeypatch, tmp_path):
    class QuietUI:
        def phase(self, *_): pass
        def warn(self, *_): pass

    cfg={'project': {'output_dir': str(tmp_path)}, 'scope': {'roots': ['example.com'], 'include_hosts': [], 'exclude_hosts': [], 'exclude_regex': []}, 'http': {'headers': [], 'proxy': '', 'timeout': 1, 'threads': 1, 'rps': 1, 'verify_tls': False}}
    pipeline=Pipeline(cfg, QuietUI(), dry_run=True);pipeline.urls=['https://app.example.com/a?q=one'];pipeline.write_lines(pipeline.art/'urls.txt',pipeline.urls)
    monkeypatch.setattr('rifthound.pipeline.which_tool',lambda name:'/usr/bin/'+name if name in {'gf','kxss'} else None)
    calls=[]
    def run(name,cmd,stdin=None,**_):
        calls.append((name,stdin));return (0,'https://app.example.com/x?query=one\n','') if name=='gf-xss' else (0,'','')
    monkeypatch.setattr(pipeline,'run_cmd',run);monkeypatch.setattr(pipeline,'native',lambda *_:None)
    pipeline.phase2()
    assert next(stdin for name,stdin in calls if name=='kxss')=='https://app.example.com/a?q=one\nhttps://app.example.com/x?query=one\n'


def test_gf_command_injection_routes_are_leads_only(tmp_path):
    (tmp_path/'cmdi.txt').write_text('https://app.example.com/run?command=echo\n')
    lead=parse_gf_leads(tmp_path)[0]
    assert lead['family']=='CMDI'
    assert lead['confidence']=='candidate'
    assert lead['tools']==['gf']


def test_jsattack_and_arjun_import_safe_leads(tmp_path):
    js=tmp_path/'report.json';js.write_text('{"sinks":[{"url":"https://app.example.com/app.js"}],"secrets":[{"url":"https://app.example.com/app.js","value":"do-not-copy"}]}')
    arjun=tmp_path/'arjun.json';arjun.write_text('{"https://app.example.com/search":["query"]}')
    js_rows=parse_jsattack(js)
    assert len(js_rows)==2 and all('value' not in row for row in js_rows)
    assert parse_arjun(arjun)[0]['parameter']=='query'


def test_engine_uses_a_session_per_worker():
    engine=Engine([],threads=2,rps=0)
    import concurrent.futures, threading
    barrier=threading.Barrier(2)
    def session_id(_):
        barrier.wait()
        return id(engine.session())
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        sessions=list(pool.map(session_id,range(2)))
    assert len(set(sessions))==2


def test_visual_report_has_filters_gates_and_artifacts(tmp_path):
    output=tmp_path/'report.html'
    write_html(output,{'urls':1,'preset':'balanced','author':'tester'},[{'confidence_score':42,'status':'lead','family':'CMDI','url':'https://app.example.com/run','tools':['gf'],'evidence_gate':['Confirm a harmless control'],'negative_controls':['Fresh baseline']}],[])
    page=output.read_text()
    assert 'Copy handoff' in page
    assert 'Evidence gates' in page
    assert 'evidence-ledger.json' in page
    assert 'data-family="CMDI"' in page


def test_reconner_import_filters_and_tracks_sources(tmp_path):
    (tmp_path/'katana.txt').write_text('https://app.example.com/a\nhttps://evil.invalid/x\n')
    (tmp_path/'js_endpoints.txt').write_text('https://api.example.com/v1\nhttps://api.example.com/'+"'"+'bad\n')
    imported=import_artifacts(tmp_path,['example.com'])
    assert imported['sources']=={'katana':1,'js-endpoints':1}
    assert imported['urls']==['https://app.example.com/a','https://api.example.com/v1']
