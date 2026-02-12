# Makefile for Threat Modeling Data

.PHONY: init full-build-mkdocs test check-yaml

init:
	sudo uv pip install --system -e /workspaces/threat-model-tool/tree-node
	sudo uv pip install --system -e /workspaces/threat-model-tool

test: check-yaml

check-yaml:
	uv run --project /workspaces/threat-model-tool python -m r3threatmodeling.checkYAMLFullDirectory \
		--TMDirectory threatModels

full-build-mkdocs:
	uv run --project /workspaces/threat-model-tool python -m r3threatmodeling.fullBuildDirectory \
		--TMDirectory threatModels \
		--outputDir build/docs \
		--template TM_templateMKDOCS \
		--formatYAML \
		--assetDir threatModels/assets \
		--templateSiteFolderSRC security_site/mkdocs \
		--templateSiteFolderDST build \
		--MKDocsSiteDir public \
