#!/bin/bash
# Development setup script for threat-model-tool

set -e

echo "🔧 Setting up threat-model-tool for development..."

# Check Python version
python3 -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"
echo "✓ Python version check passed"

# Install TreeNode package in development mode
echo "📦 Installing TreeNode package..."
cd tree-node
pip install -e .
cd ..
echo "✓ TreeNode installed"

# Install main package in development mode
echo "📦 Installing r3threatmodeling package..."
pip install -e .
echo "✓ r3threatmodeling installed"

# Install development dependencies
echo "📦 Installing development dependencies..."
pip install -r requirements-dev.txt
echo "✓ Development dependencies installed"

# Verify installation
echo "🧪 Verifying installation..."
python3 -c "from tree_node import TreeNode; print('✓ TreeNode import OK')"
python3 -c "from r3threatmodeling import TreeNode; print('✓ r3threatmodeling import OK')"

# Run tests
echo "🧪 Running tests..."
python3 tests/test_tree_extraction.py
python3 tree-node/tests/test_tree_node.py

echo ""
echo "🎉 Development setup complete!"
echo ""
echo "You can now:"
echo "  • Import TreeNode independently: from tree_node import TreeNode"
echo "  • Import from r3threatmodeling: from r3threatmodeling import TreeNode"
echo "  • Run the threat modeling tools"
echo "  • Make changes to either package and see them immediately"
