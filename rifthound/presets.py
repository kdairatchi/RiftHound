from copy import deepcopy
PRESETS={
'passive':{'description':'Passive recon + fingerprints only','phases':[1],'threads':4,'rps':4},
'quick':{'description':'Fast recon, JS/DOM and reflection pass','phases':[1,2,4],'threads':6,'rps':8},
'balanced':{'description':'Recommended all-phase bug-bounty preset','phases':[1,2,3,4],'threads':5,'rps':6},
'deep':{'description':'Deep discovery + low-impact validators','phases':[1,2,3,4],'threads':6,'rps':5},
'full':{'description':'Maximum safe automatic workflow','phases':[1,2,3,4],'threads':6,'rps':4},
'xss':{'description':'Reflection/DOM/XSS specialization','phases':[1,2,3,4],'threads':6,'rps':6},
'client':{'description':'postMessage/browser/client trust specialization','phases':[1,2,3,4],'threads':5,'rps':5},
'api':{'description':'REST/OpenAPI/GraphQL/API auth specialization','phases':[1,2,3,4],'threads':5,'rps':5},
'auth':{'description':'OAuth/OIDC/SAML/recovery specialization','phases':[2,3,4],'threads':4,'rps':4},
'cache':{'description':'Cache/CDN/canonical-host specialization','phases':[1,2,3,4],'threads':4,'rps':4},
'server':{'description':'Safe server-side validators','phases':[1,2,3,4],'threads':5,'rps':4},
'wordpress':{'description':'WordPress/plugin/API/client specialization','phases':[1,2,3,4],'threads':5,'rps':5},
}
def get_preset(name): return deepcopy(PRESETS[name])
