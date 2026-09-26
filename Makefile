# guard-core-php Makefile, harmonized with the guard-core (Python) family.
# This host has no php/composer binaries: every target falls back to the
# documented Docker runners (php:8.3-cli, composer:2) when the local
# binary is missing. Host Redis on 6379 is reachable from containers as
# host.docker.internal (see AGENTS.md).

PHP_IMAGE ?= php:8.3-cli
COMPOSER_IMAGE ?= composer:2
REDIS_HOST ?= host.docker.internal

# Runners mirrored from CI (.github/workflows/ci.yml). Redis-backed
# runners are listed in REDIS_RUNNERS and get REDIS_HOST passed through.
REDIS_RUNNERS = bin/test_ratelimit.php bin/test_geo_rate_limits.php bin/test_pipeline.php bin/test_m3b.php bin/test_m4.php
RUNNERS = bin/test_state.php $(REDIS_RUNNERS) bin/test_m3c.php bin/conformance.php bin/test_nfkc.php bin/test_binary_noise_gate.php bin/test_recon_context_gate.php bin/test_recon_raw_view_scan.php bin/test_body_form_scan.php bin/test_json_walk.php bin/test_exempt_ips.php bin/test_excluded_headers.php bin/test_cors.php bin/test_geo_country.php bin/test_large_body.php

.PHONY: install test lint bump-version clean

install:
	@if command -v composer > /dev/null 2>&1; then \
		composer install --no-interaction --no-progress; \
	else \
		echo "composer not found locally, using $(COMPOSER_IMAGE)"; \
		docker run --rm -v "$$PWD":/app -w /app $(COMPOSER_IMAGE) composer install --no-interaction --no-progress; \
	fi

test:
	@if command -v php > /dev/null 2>&1; then \
		runner="php"; \
	else \
		echo "php not found locally, using $(PHP_IMAGE)"; \
		runner="docker run --rm -v $$PWD:/app -w /app -e REDIS_HOST=$(REDIS_HOST) $(PHP_IMAGE) php"; \
	fi; \
	status=0; \
	for r in $(RUNNERS); do \
		echo "== $$r =="; \
		case " $(REDIS_RUNNERS) " in \
			*" $$r "*) \
				REDIS_HOST="$${REDIS_HOST:-127.0.0.1}" $$runner "$$r" || status=1; \
				;; \
			*) \
				$$runner "$$r" || status=1; \
				;; \
		esac; \
	done; \
	exit $$status

lint:
	@if command -v php > /dev/null 2>&1; then \
		php_lint="php -l"; \
		composer_cmd="composer validate --strict"; \
	else \
		echo "php not found locally, using $(PHP_IMAGE)"; \
		php_lint="docker run --rm -v $$PWD:/app -w /app $(PHP_IMAGE) php -l"; \
		composer_cmd="docker run --rm -v $$PWD:/app -w /app $(COMPOSER_IMAGE) composer validate --strict"; \
	fi; \
	status=0; \
	for f in $$(find src bin -name '*.php'); do \
		$$php_lint "$$f" > /dev/null || status=1; \
	done; \
	if [ $$status -eq 0 ]; then echo "LINT_OK"; else echo "LINT_FAILED"; fi; \
	$$composer_cmd || status=1; \
	exit $$status

bump-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make bump-version VERSION=x.y.z"; \
		exit 1; \
	fi; \
	python3 .github/scripts/bump_version.py $(VERSION)

clean:
	@rm -rf vendor site 2>/dev/null; \
	find . -name '*.cache' -delete 2>/dev/null; \
	echo "cleaned vendor/, site/ and cache files"
