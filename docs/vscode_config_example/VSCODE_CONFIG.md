# Setup Workspace with DevContainer

Guide to setting up a dual-project workspace: `threat-modeling` (YAML models) and `threat-model-tool` (Python code) as siblings.

## 1. Folder Setup

Ensure both repositories are in the same parent directory:

```bash
mkdir my-project && cd my-project
git clone <yaml-models-repo-url> threat-modeling
git clone <tool-repo-url> threat-model-tool
```

## 2. Copy Configuration Files

From your local terminal, copy the template files into the modeling folder:

```bash
cd threat-modeling
cp -r ../threat-model-tool/docs/vscode_config_example/.devcontainer .
cp ../threat-model-tool/docs/vscode_config_example/threat-modeling.code-workspace .
```

## 3. Open Workspace

1. Open VS Code: `code threat-modeling.code-workspace`
2. Click **Reopen in Container** when prompted.
3. Wait for the build to finish (it installs `tree-node` and `r3threatmodeling` in editable mode automatically).

## 4. Basic Usage

### View Reports
Generated reports are located in the `build/` directory.

## Note on Tool Changes
The tool is installed via `pip install -e`. Any changes you make in `threat-model-tool/src/` are applied immediately without needing a reinstall or container rebuild.
