# TreeNode - A Reusable Tree Structure Library

A lightweight, reusable Python library for creating hierarchical tree structures with parent-child relationships and ID management.

## Features

- **Hierarchical ID Management**: Automatic generation of hierarchical IDs (e.g., `parent.child.grandchild`)
- **Parent-Child Relationships**: Automatic management of bidirectional parent-child relationships
- **Tree Navigation**: Methods to traverse up and down the tree structure
- **Flexible Data Storage**: Initialize nodes with dictionary data
- **Type-Safe Traversal**: Find nodes by type or ID throughout the tree
- **URI Generation**: Generate URI representations for nodes

## Installation

### From Source (within threat-model-tool repo)

```bash
cd tree-node
pip install -e .
```

### Standalone Installation

```bash
pip install tree-node
```

## Quick Start

```python
from tree_node import TreeNode

# Create a root node
root = TreeNode({'ID': 'root'})

# Create child nodes - parent-child relationships are automatic
child1 = TreeNode({'ID': 'child1'}, parent=root)
child2 = TreeNode({'ID': 'child2'}, parent=root)
grandchild = TreeNode({'ID': 'grandchild'}, parent=child1)

# Access hierarchical IDs
print(root.id)        # 'root'
print(child1.id)     # 'root.child1'
print(grandchild.id) # 'root.child1.grandchild'

# Navigate the tree
print(f"Root has {len(root.children)} children")
print(f"Child1's parent: {child1.parent.id}")

# Find nodes
found = root.getDescendantById('grandchild')
print(f"Found: {found.id}")

# Get all nodes of a specific type
all_nodes = root.getAllDownByType(TreeNode)
print(f"Total nodes in tree: {len(all_nodes)}")
```

## Advanced Usage

### Custom Node Classes

```python
class CustomNode(TreeNode):
    def __init__(self, data=None, parent=None, custom_attr=None):
        super().__init__(data, parent)
        self.custom_attr = custom_attr

# Use your custom node class
root = CustomNode({'ID': 'root'}, custom_attr='root_value')
child = CustomNode({'ID': 'child'}, parent=root, custom_attr='child_value')
```

### Tree Traversal

```python
# Get all values of an attribute going up the tree
values_up = node.getAllUp('some_attribute')

# Get all values of an attribute going down the tree  
values_down = node.getAllDown('some_attribute')

# Get the first occurrence of an attribute going up
first_value = node.getFirstUp('some_attribute')

# Get the root of the tree
root = node.getRoot()
```

## API Reference

### TreeNode Class

#### Constructor
- `TreeNode(dict_data=None, parent=None)`
  - `dict_data`: Optional dictionary with node data (must contain 'ID' key)
  - `parent`: Optional parent TreeNode

#### Properties
- `id`: Full hierarchical ID of the node
- `anchor`: The local ID part (excluding parent hierarchy)
- `uri`: URI representation of the node

#### Methods
- `getRoot()`: Get the root node of the tree
- `getDescendantById(target_id)`: Find a descendant by ID
- `getDescendantFirstById(target_id)`: Get any descendant by ID (searches all levels)
- `getAllUp(attr_name)`: Get attribute values going up the tree
- `getAllDown(attr_name)`: Get attribute values going down the tree
- `getFirstUp(attr_name)`: Get first attribute value going up the tree
- `getAllDownByType(type_class)`: Get all nodes of a specific type in subtree

## Integration with r3threatmodeling

This TreeNode library was extracted from the r3threatmodeling package and is designed to work seamlessly with it:

```python
# Can be used independently
from tree_node import TreeNode

# Or as part of r3threatmodeling (which imports from this module)
from r3threatmodeling import TreeNode
```

## Requirements

- Python 3.8+
- No external dependencies

## License

Apache-2.0 License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
