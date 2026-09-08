.PHONY: test doctor smoke

test:
	PYTHONPATH=. python3 -m pytest -q

doctor:
	PYTHONPATH=. python3 -m rifthound doctor

smoke:
	PYTHONPATH=. python3 -m rifthound --version
	PYTHONPATH=. python3 -m rifthound steps | tail -3
