from rifthound.steps import STEP_CATALOG
from rifthound.presets import PRESETS
from rifthound.chains import RULES,generate
from rifthound.scope import host_in_roots,url_in_scope,normalize_url

def test_steps_001_130():
 assert len(STEP_CATALOG)==130
 assert [x['step'] for x in STEP_CATALOG]==list(range(1,131))
 assert STEP_CATALOG[0]['id']=='STEP-001' and STEP_CATALOG[-1]['id']=='STEP-130'

def test_presets():
 assert len(PRESETS)==12 and 'balanced' in PRESETS and 'wordpress' in PRESETS

def test_scope():
 assert host_in_roots('api.example.com',['example.com'])
 assert url_in_scope('https://api.example.com/v1',['example.com'])
 assert not url_in_scope('https://evil.example.net/',['example.com'])
 assert normalize_url('example.com')=='https://example.com/'

def test_chain_catalog():
 assert len(RULES)>=120
 inv={'app.example.com':{'surfaces':['postmessage','oauth'],'examples':{}}}
 ids={x['id'] for x in generate(inv,[])}
 assert 'RH-CHAIN-000' in ids
