"""
Example usage of the TreeNode class in another project.
This demonstrates how the extracted TreeNode can be reused independently.
"""

from r3threatmodeling.tree_node import TreeNode


class ExampleNode(TreeNode):
    """Example class showing how to extend TreeNode for another project."""
    
    def __init__(self, dict_data=None, parent=None, name=None):
        super().__init__(dict_data, parent)
        self.name = name or getattr(self, '_id', 'unnamed')
        self.custom_data = []
    
    def add_custom_data(self, data):
        """Add custom data to this node."""
        self.custom_data.append(data)
    
    def __str__(self):
        return f"ExampleNode(id={self.id}, name={self.name})"


def main():
    """Demonstrate TreeNode usage in another project."""
    
    # Create root node
    root = ExampleNode({'ID': 'root'}, name='Root Node')
    root.add_custom_data('Root data')
    
    # Create child nodes
    child1 = ExampleNode({'ID': 'child1'}, parent=root, name='First Child')
    child1.add_custom_data('Child 1 data')
    
    child2 = ExampleNode({'ID': 'child2'}, parent=root, name='Second Child') 
    child2.add_custom_data('Child 2 data')
    
    # Create grandchild
    grandchild = ExampleNode({'ID': 'grandchild'}, parent=child1, name='Grandchild')
    grandchild.add_custom_data('Grandchild data')
    
    # Demonstrate tree functionality
    print("Tree structure:")
    print(f"Root: {root}")
    print(f"  Children: {len(root.children)}")
    for child in root.children:
        print(f"    {child}")
        if hasattr(child, 'children') and child.children:
            for grandchild in child.children:
                print(f"      {grandchild}")
    
    print(f"\nHierarchical IDs:")
    print(f"Root ID: {root.id}")
    print(f"Child1 ID: {child1.id}")
    print(f"Child2 ID: {child2.id}")
    print(f"Grandchild ID: {grandchild.id}")
    
    print(f"\nTree traversal:")
    print(f"Root is root: {root.getRoot().id}")
    print(f"Grandchild root: {grandchild.getRoot().id}")
    
    # Find descendant by ID
    found = root.getDescendantById('grandchild')
    print(f"Found grandchild: {found}")
    
    # Get all nodes of specific type
    all_nodes = root.getAllDownByType(ExampleNode)
    print(f"All ExampleNode instances: {len(all_nodes)}")
    for node in all_nodes:
        print(f"  {node}")


if __name__ == '__main__':
    main()
