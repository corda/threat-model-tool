import sys
import os
import pytest

# Add src and tree-node/src to path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../tree-node/src')))

from tree_node import TreeNode
from r3threatmodeling import threatmodel_data

def test_tree_node_independent():
    """Test TreeNode can be used independently."""
    root = TreeNode({'ID': 'root'})
    child1 = TreeNode({'ID': 'child1'}, parent=root)
    assert root.id == 'root'
    assert child1.id == 'root.child1'

def test_threat_model_integration():
    """Test integrated usage with ThreatModel."""
    base_path = os.path.dirname(__file__)
    tm_path = os.path.join(base_path, "exampleThreatModels/FullFeature/FullFeature.yaml")
    tm = threatmodel_data.ThreatModel(tm_path)
    
    # ThreatModel should be a TreeNode
    assert isinstance(tm, TreeNode)
    assert tm.id == 'FullFeature'
