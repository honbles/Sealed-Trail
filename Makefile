.PHONY: crypto test test-fast run-inproc run-local compose docker-build up

BANKS ?= 3
ACCOUNTS ?= 2
VALIDATORS ?= 4
BYZ ?= 1
PAYMENTS ?= 20
STCTL = python3 -m sealedtrail.nodes.stctl

crypto:
	cd crypto && cargo build --release --locked
test: crypto
	python3 -m pytest tests -q
test-fast: crypto
	python3 -m pytest tests -q -m "not nodes"
run-inproc: crypto
	$(STCTL) run --runtime inproc --banks $(BANKS) --accounts-per-bank $(ACCOUNTS) --validators $(VALIDATORS) --byzantine $(BYZ) --payments $(PAYMENTS)
run-local: crypto
	$(STCTL) run --runtime local --banks $(BANKS) --accounts-per-bank $(ACCOUNTS) --validators $(VALIDATORS) --byzantine $(BYZ) --payments $(PAYMENTS)
compose:
	$(STCTL) compose --banks $(BANKS) --accounts-per-bank $(ACCOUNTS) --validators $(VALIDATORS) --byzantine $(BYZ)
docker-build: compose
	docker build -f run/Dockerfile -t sealed-trail:latest .
up: docker-build
	docker compose -f run/docker-compose.yml up -d
