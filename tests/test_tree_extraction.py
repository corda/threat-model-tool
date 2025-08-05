#!/usr/bin/env python3
"""
Test script to verify TreeNode extraction was successful.
This tests both independent usage of TreeNode and integration with original code.
"""

import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_tree_node_independent():
    """Test TreeNode can be used independently."""
    print("Testing TreeNode independent usage...")
    
    from r3threatmodeling.tree_node import TreeNode
    
    # Create a simple tree
    root = TreeNode({'ID': 'root'})
    child1 = TreeNode({'ID': 'child1'}, parent=root)
    child2 = TreeNode({'ID': 'child2'}, parent=root)
    grandchild = TreeNode({'ID': 'grandchild'}, parent=child1)
    
    # Test hierarchical IDs
    assert root.id == 'root', f"Expected 'root', got '{root.id}'"
    assert child1.id == 'root.child1', f"Expected 'root.child1', got '{child1.id}'"
    assert child2.id == 'root.child2', f"Expected 'root.child2', got '{child2.id}'"
    assert grandchild.id == 'root.child1.grandchild', f"Expected 'root.child1.grandchild', got '{grandchild.id}'"
    
    # Test parent-child relationships
    assert len(root.children) == 2, f"Expected 2 children, got {len(root.children)}"
    assert child1 in root.children, "child1 should be in root.children"
    assert child2 in root.children, "child2 should be in root.children"
    assert len(child1.children) == 1, f"Expected 1 grandchild, got {len(child1.children)}"
    assert grandchild in child1.children, "grandchild should be in child1.children"
    
    # Test tree traversal
    assert grandchild.getRoot() == root, "grandchild.getRoot() should return root"
    found = root.getDescendantById('grandchild')
    assert found == grandchild, f"Expected to find grandchild, got {found}"
    
    # Test type search
    all_nodes = root.getAllDownByType(TreeNode)
    assert len(all_nodes) == 4, f"Expected 4 nodes, got {len(all_nodes)}"  # root + 2 children + 1 grandchild
    
    print("✓ TreeNode independent usage test passed")


def test_threat_model_integration():
    """Test that TreeNode integration with threat model classes works."""
    print("Testing TreeNode integration with threat model classes...")
    
    from r3threatmodeling.threatmodel_data import BaseThreatModelObject
    from r3threatmodeling.tree_node import TreeNode
    
    # Create a BaseThreatModelObject (which extends TreeNode)
    obj = BaseThreatModelObject({'ID': 'test_object'})
    
    # Test that it has TreeNode functionality
    assert obj.id == 'test_object'
    assert isinstance(obj, TreeNode)
    assert obj.getRoot() == obj
    
    # Create child objects
    child = BaseThreatModelObject({'ID': 'child_object'}, parent=obj)
    assert child.id == 'test_object.child_object'
    assert len(obj.children) == 1
    assert child in obj.children
    
    print("✓ TreeNode integration test passed")


def test_package_imports():
    """Test that TreeNode can be imported from package level."""
    print("Testing package-level imports...")
    
    # Test direct import from tree_node module
    from r3threatmodeling.tree_node import TreeNode
    node1 = TreeNode({'ID': 'direct'})
    assert node1.id == 'direct'
    
    # Test import from package __init__
    from r3threatmodeling import TreeNode as TreeNodePackage
    node2 = TreeNodePackage({'ID': 'package'})
    assert node2.id == 'package'
    
    # Verify they're the same class
    assert TreeNode is TreeNodePackage
    
    print("✓ Package import test passed")


def main():
    """Run all tests."""
    print("Running TreeNode extraction verification tests...\n")
    
    try:
        test_tree_node_independent()
        test_threat_model_integration()
        test_package_imports()
        
        print("\n🎉 All tests passed! TreeNode extraction was successful.")
        print("\nThe TreeNode class has been successfully extracted to its own module and can be:")
        print("1. Used independently in other projects")
        print("2. Imported from r3threatmodeling.tree_node")
        print("3. Imported from the main r3threatmodeling package")
        print("4. Extended by threat model classes as before")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
