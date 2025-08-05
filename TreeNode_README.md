# TreeNode Module

A reusable tree structure implementation that provides hierarchical node functionality with parent-child relationships and ID management. This module is designed to be used across different projects that need tree structures.

## Features

- **Hierarchical ID Management**: Automatically constructs full hierarchical IDs (e.g., "parent.child.grandchild")
- **Parent-Child Relationships**: Automatic bidirectional linking between parent and child nodes
- **Tree Traversal**: Methods to traverse up and down the tree structure
- **Attribute Aggregation**: Collect attributes from multiple levels in the tree
- **ID Validation**: Ensures IDs contain only alphanumeric characters and underscores
- **Search Functionality**: Find nodes by ID or type within the tree

## Installation

The TreeNode class is part of the r3threatmodeling package:

```python
from r3threatmodeling.tree_node import TreeNode
```

Or import from the main package:

```python
from r3threatmodeling import TreeNode
```

## Basic Usage

### Creating a Tree Structure

```python
from r3threatmodeling.tree_node import TreeNode

# Create root node
root = TreeNode({'ID': 'root'})

# Create child nodes - they automatically link to parent
child1 = TreeNode({'ID': 'child1'}, parent=root)
child2 = TreeNode({'ID': 'child2'}, parent=root)

# Create grandchild
grandchild = TreeNode({'ID': 'grandchild'}, parent=child1)

print(f"Root ID: {root.id}")           # Output: root
print(f"Child1 ID: {child1.id}")       # Output: root.child1  
print(f"Grandchild ID: {grandchild.id}") # Output: root.child1.grandchild
```

### Extending TreeNode

```python
class MyNode(TreeNode):
    def __init__(self, dict_data=None, parent=None, custom_attr=None):
        super().__init__(dict_data, parent)
        self.custom_attr = custom_attr or []
    
    def add_data(self, data):
        self.custom_attr.append(data)

# Use your custom node
root = MyNode({'ID': 'root'})
child = MyNode({'ID': 'child'}, parent=root, custom_attr=['some', 'data'])
```

## API Reference

### Properties

- **`id`**: Get/set the full hierarchical ID of the node
- **`anchor`**: Get the anchor part of the ID (excluding parent hierarchy)
- **`uri`**: Get the URI representation of the node

### Core Methods

- **`getRoot()`**: Get the root node of the tree
- **`getAllUp(attr_name)`**: Get all values of an attribute from this node up to the root
- **`getFirstUp(attr_name)`**: Get the first occurrence of an attribute going up the tree
- **`getAllDown(attr_name)`**: Get all values of an attribute from this node down through all children
- **`getAllDownByType(type_class)`**: Get all objects of a specific type in the tree rooted at this node
- **`getDescendantById(target_id)`**: Get a descendant by ID within this node's children

### Initialization Parameters

- **`dict_data`** (optional): Dictionary containing node data (must have 'ID' key if provided)
- **`parent`** (optional): Parent node reference

## Tree Traversal Examples

### Finding Nodes

```python
# Find by ID
node = root.getDescendantById('child1')

# Find all nodes of specific type
all_my_nodes = root.getAllDownByType(MyNode)
```

### Collecting Attributes

```python
# Get all 'data' attributes going up the tree
data_up = node.getAllUp('data')

# Get all 'data' attributes going down the tree  
data_down = root.getAllDown('data')

# Get first 'config' attribute found going up
config = node.getFirstUp('config')
```

## Children Collection

The TreeNode automatically maintains a `children` set containing all child nodes:

```python
root = TreeNode({'ID': 'root'})
child1 = TreeNode({'ID': 'child1'}, parent=root)
child2 = TreeNode({'ID': 'child2'}, parent=root)

print(f"Root has {len(root.children)} children")
for child in root.children:
    print(f"Child: {child.id}")
```

## ID Validation

TreeNode validates that IDs only contain alphanumeric characters and underscores:

```python
try:
    node = TreeNode({'ID': 'invalid-id'})  # Will raise ValueError
except ValueError as e:
    print(f"ID validation error: {e}")

# Valid IDs
valid_node = TreeNode({'ID': 'valid_id_123'})  # OK
```

## Use Cases

The TreeNode class is suitable for:

- Configuration hierarchies
- Organizational structures  
- Category/taxonomy trees
- File system representations
- Threat modeling structures
- Any hierarchical data that needs ID management and tree traversal

## Thread Safety

TreeNode is not thread-safe. If you need to use it in a multi-threaded environment, you should implement appropriate locking mechanisms.
