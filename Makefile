# Default arguments for the threat model tool
TM_DIR ?= tests/exampleThreatModels
OUTPUT_DIR ?= build
ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TOTEST_DIR ?= $(ROOT_DIR)/build/totest
TOTEST_OUTPUT_PY ?= $(TOTEST_DIR)/output_python
TOTEST_OUTPUT_TS ?= $(TOTEST_DIR)/output_ts

.PHONY: init test build run-example debug clean build-totest-python build-totest-ts compare-totest-md compare-totest-puml compare-totest-current compare-totest

init:
	sudo uv pip install --system -e ./tree-node
	sudo uv pip install --system -e .
	npm install
	cd threat-model-tool-js && npm install

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

compare-totest-puml:
	python3 $(ROOT_DIR)/scripts/compare_totest.py --mode puml --base $(TOTEST_DIR)

compare-totest-current: compare-totest-md compare-totest-puml

compare-totest: build-totest-python build-totest-ts compare-totest-md compare-totest-puml
