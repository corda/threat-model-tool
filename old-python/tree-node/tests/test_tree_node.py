"""
Test TreeNode independent functionality
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from tree_node import TreeNode


def test_basic_functionality():
    """Test basic TreeNode functionality."""
    print("Testing basic TreeNode functionality...")
    
    # Create nodes
    root = TreeNode({'ID': 'root'})
    child1 = TreeNode({'ID': 'child1'}, parent=root)
    child2 = TreeNode({'ID': 'child2'}, parent=root)
    grandchild = TreeNode({'ID': 'grandchild'}, parent=child1)
    
    # Test IDs
    assert root.id == 'root'
    assert child1.id == 'root.child1'
    assert child2.id == 'root.child2'
    assert grandchild.id == 'root.child1.grandchild'
    
    # Test parent-child relationships
    assert len(root.children) == 2
    assert child1.parent == root
    assert child2.parent == root
    assert grandchild.parent == child1
    
    # Test tree navigation
    assert root.getRoot() == root
    assert grandchild.getRoot() == root
    
    # Test finding descendants
    found = root.getDescendantById('grandchild')
    assert found == grandchild
    
    found_first = root.getDescendantFirstById('grandchild')
    assert found_first == grandchild
    
    # Test getting all nodes by type
    all_nodes = root.getAllDownByType(TreeNode)
    assert len(all_nodes) == 4  # root + child1 + child2 + grandchild
    
    print("✓ Basic TreeNode functionality test passed")


def test_custom_node_class():
    """Test TreeNode can be extended."""
    print("Testing custom node class...")
    
    class CustomNode(TreeNode):
        def __init__(self, data=None, parent=None, custom_attr=None):
            super().__init__(data, parent)
            self.custom_attr = custom_attr
    
    root = CustomNode({'ID': 'root'}, custom_attr='root_value')
    child = CustomNode({'ID': 'child'}, parent=root, custom_attr='child_value')
    
    assert root.id == 'root'
    assert child.id == 'root.child'
    assert root.custom_attr == 'root_value'
    assert child.custom_attr == 'child_value'
    assert isinstance(child, TreeNode)
    assert isinstance(child, CustomNode)
    
    print("✓ Custom node class test passed")


def test_attribute_traversal():
    """Test getting attributes up and down the tree."""
    print("Testing attribute traversal...")
    
    root = TreeNode({'ID': 'root'})
    child = TreeNode({'ID': 'child'}, parent=root)
    grandchild = TreeNode({'ID': 'grandchild'}, parent=child)
    
    # Add some test attributes
    root.test_attr = ['root_value']
    child.test_attr = ['child_value']
    grandchild.test_attr = ['grandchild_value']
    
    # Test getAllUp
    up_values = grandchild.getAllUp('test_attr')
    assert 'root_value' in str(up_values)
    assert 'child_value' in str(up_values)
    assert 'grandchild_value' in str(up_values)
    
    # Test getFirstUp
    first_up = grandchild.getFirstUp('test_attr')
    assert first_up == ['grandchild_value']
    
    # Test getAllDown from root
    down_values = root.getAllDown('test_attr')
    assert 'root_value' in str(down_values)
    assert 'child_value' in str(down_values)
    assert 'grandchild_value' in str(down_values)
    
    print("✓ Attribute traversal test passed")


if __name__ == "__main__":
    test_basic_functionality()
    test_custom_node_class()
    test_attribute_traversal()
    print("\n✅ All TreeNode independent tests passed!")
