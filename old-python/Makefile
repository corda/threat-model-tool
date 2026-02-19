# Default arguments for the threat model tool
TM_DIR ?= tests/exampleThreatModels
OUTPUT_DIR ?= build
ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TOTEST_DIR ?= $(ROOT_DIR)/build/totest
TOTEST_OUTPUT_PY ?= $(TOTEST_DIR)/output_python
TOTEST_OUTPUT_TS ?= $(TOTEST_DIR)/output_ts

.PHONY: init test build run-example debug clean build-totest-python build-totest-ts compare-totest-md compare-totest-html compare-totest-puml compare-totest-current compare-totest render-totest-puml-tsvg

init:
	sudo uv pip install --system -e ./tree-node
	sudo uv pip install --system -e .
	npm install
	cd threat-model-tool-js && npm install
	cd threat-model-tool-js/astro-site && npm install
	cd threat-model-tool-js/docusaurus-site && npm install
	cd threat-model-tool-js/hugo-site && npm install

test:
	uv run pytest

build:
	uv build

run-example:
	uv run python -m r3threatmodeling.fullBuildDirectory \
		--TMDirectory $(TM_DIR) \
		--outputDir $(OUTPUT_DIR) \
		--generatePDF \
		--formatYAML \
		--templateSiteFolderSRC tests/siteTemplate/mkdocs \
		--templateSiteFolderDST build/mkdocs/ \
		--MKDocsSiteDir public \
		--MKDocsDir build/mkdocs

check-yaml:
	uv run python -m r3threatmodeling.checkYAMLFullDirectory \
		--TMDirectory $(TM_DIR)

check-single-yaml:
	uv run python -m r3threatmodeling.checkSingleYAMLfile \
		--tmYAMLfile $(TM_FILE)

upgrade-yaml-dryrun:
	uv run python -m r3threatmodeling.normalizeYAML \
		--rootTMYaml $(TM_FILE) \
		--dryRun

upgrade-yaml-inplace:
	uv run python -m r3threatmodeling.normalizeYAML \
		--rootTMYaml $(TM_FILE)

debug:
	uv run python -m debugpy --listen 5678 --wait-for-client -m r3threatmodeling.fullBuildDirectory \
		--TMDirectory $(TM_DIR) \
		--outputDir $(OUTPUT_DIR) \
		--generatePDF \
		--formatYAML \
		--templateSiteFolderSRC tests/siteTemplate/mkdocs \
		--templateSiteFolderDST build/mkdocs/ \
		--MKDocsSiteDir public \
		--MKDocsDir build/mkdocs

clean:
	rm -rf dist/ build/ public/ .pytest_cache/

build-totest-python:
	uv run python -m r3threatmodeling.fullBuildDirectory \
		--TMDirectory $(TOTEST_DIR) \
		--outputDir $(TOTEST_OUTPUT_PY)

build-totest-ts:
	cd $(ROOT_DIR)/threat-model-tool-js && \
	for dir in $(TOTEST_DIR)/*/; do \
		name=$$(basename "$$dir"); \
		if [ -f "$$dir/$$name.yaml" ]; then \
			npx tsx src/scripts/build-threat-model.ts \
				"$$dir/$$name.yaml" \
				"$(TOTEST_OUTPUT_TS)/$$name"; \
		fi; \
	done

compare-totest-md:
	python3 $(ROOT_DIR)/scripts/compare_totest.py --mode md --base $(TOTEST_DIR)

compare-totest-html:
	python3 $(ROOT_DIR)/scripts/compare_totest.py --mode html --base $(TOTEST_DIR)

compare-totest-puml:
	python3 $(ROOT_DIR)/scripts/compare_totest.py --mode puml --base $(TOTEST_DIR)

render-totest-puml-tsvg:
	@if command -v plantuml >/dev/null 2>&1; then \
		find "$(TOTEST_OUTPUT_PY)" "$(TOTEST_OUTPUT_TS)" -type f -name '*.puml' -exec plantuml -tsvg {} +; \
	else \
		echo "plantuml command not found on PATH. Skipping explicit -tsvg rendering target."; \
	fi

compare-totest-current: compare-totest-md compare-totest-html compare-totest-puml

compare-totest: build-totest-python build-totest-ts render-totest-puml-tsvg compare-totest-md compare-totest-html compare-totest-puml

build-site-ts:
	cd threat-model-tool-js && npm run build:astroSite:examples

build-site-docusaurus-ts:
	cd threat-model-tool-js && npm run build:docusaurusSite:examples

build-site-hugo-ts:
	cd threat-model-tool-js && npm run build:hugoSite:examples

build-site-mkdocs-ts:
	cd threat-model-tool-js && npm run build:mkdocsSite:examples
