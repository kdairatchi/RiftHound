# RiftHound validation gates

For a serious candidate prove: baseline absence, one-input attribution, isolated repetition, fresh canary, counterfactual control, transport/cache/WAF exclusion, sink/security-boundary context, controlled impact, cleanup, and explicit report state.

Common false positives include challenge pages that echo the requested URL, unstable dynamic bodies, cross-host redirects, JSON echoes mistaken for XSS, cache headers mistaken for poisoning, wildcard CORS without sensitive readable data, and source/sink keywords with no data flow.
