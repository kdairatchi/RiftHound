from rifthound import tools
from rifthound.pipeline import Pipeline
from rifthound.correlation import nmap_services, metasploit_query, searchsploit_results


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
