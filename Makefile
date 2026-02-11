# Default arguments for the threat model tool
TM_DIR ?= tests/exampleThreatModels
OUTPUT_DIR ?= build

.PHONY: init test build run-example debug clean

init:
	uv pip install -e .

test:
	uv run pytest tests

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
