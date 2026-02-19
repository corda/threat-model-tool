"""
Tree Node Module

A reusable tree structure implementation that provides hierarchical node functionality
with parent-child relationships and ID management. This module is designed to be 
used across different projects that need tree structures.
"""

import re


class TreeNode:
    """
    Base class for tree node functionality, handling parent-child relationships and ID management.
    This class is designed to be reusable across different projects that need tree structures.
    """
    
    def __init__(self, dict_data=None, parent=None):
        """
        Initialize a tree node with optional dictionary data and parent reference.
        
        Args:
            dict_data: Dictionary containing node data (must have 'ID' key if provided)
            parent: Parent node reference
        """
        self.parent = parent
        
        # Add this node to parent's children collection only if parent is a TreeNode
        if parent is not None and isinstance(parent, TreeNode):
            if hasattr(parent, "children"):
                if not isinstance(parent.children, list):
                    parent.children = list(parent.children)  # Convert to list if needed
                parent.children.append(self)
            else:
                parent.children = [self]  # Use list instead of set
    
        # Set ID from dict if provided
        if dict_data and "ID" in dict_data:
            self._id = dict_data["ID"]
        else:
            self._id = "undefined"

    @property
    def id(self):
        """Get the full hierarchical ID of this node."""
        if not hasattr(self, '_id'):
            return None
        
        if self.parent is not None:
            parent_id = self.parent.id or getattr(self.parent, '_id', 'unknown')
            return f"{parent_id}.{self._id}"
        else:
            return self._id
    
    @id.setter
    def id(self, value):
        """Set the ID with validation for allowed characters."""
        if not re.match("^[a-zA-Z0-9_]*$", value):
            parent_id = self.parent.id if self.parent else "None"
            raise ValueError(f"ID can only contain alphanumeric characters and underscores. Invalid ID: {value} (parent: {parent_id})")
        self._id = value

    @property
    def anchor(self):
        """Get the anchor part of the ID (excluding parent hierarchy)."""
        full_id = self.id
        if '.' in full_id:
            return full_id[full_id.find('.')+1:]
        return full_id

    @property
    def uri(self):
        """Get the URI representation of this node."""
        if not self.parent:
            return self.id
        
        root = self.getRoot()
        root_id = getattr(root, '_id', self.id)
        return root_id + '/#' + self.anchor

    def getRoot(self):
        """Get the root node of this tree."""
        if self.parent is None:
            return self
        else:
            return self.parent.getRoot()
    
    def getAllUp(self, attr_name):
        """Get all values of an attribute recursively from this node up to the root."""
        if self.parent is None:
            return getattr(self, attr_name, [])
        else:
            parent_attrs = self.parent.getAllUp(attr_name)
            self_attrs = getattr(self, attr_name, [])
            # Handle both list and non-list attributes
            if isinstance(parent_attrs, list) and isinstance(self_attrs, list):
                return parent_attrs + self_attrs
            elif isinstance(parent_attrs, list):
                return parent_attrs + [self_attrs] if self_attrs is not None else parent_attrs
            elif isinstance(self_attrs, list):
                return ([parent_attrs] if parent_attrs is not None else []) + self_attrs
            else:
                return [parent_attrs, self_attrs] if parent_attrs is not None and self_attrs is not None else ([parent_attrs] if parent_attrs is not None else [self_attrs] if self_attrs is not None else [])

    def getFirstUp(self, attr_name):
        """Get the first occurrence of an attribute going up the tree."""
        if hasattr(self, attr_name):
            return getattr(self, attr_name)
        elif self.parent is None:
            return None
        else:
            return self.parent.getFirstUp(attr_name)
        
    def getAllDown(self, attr_name):
        """Get all values of an attribute recursively from this node down through all children."""
        ret = getattr(self, attr_name, [])
        
        # Look for standard children collections
        children_collections = []
        if hasattr(self, 'children'):
            children_collections.append(self.children)
        
        for children in children_collections:
            if children:
                for child in children:
                    if hasattr(child, 'getAllDown'):
                        child_attrs = child.getAllDown(attr_name)
                        if isinstance(ret, list) and isinstance(child_attrs, list):
                            ret = ret + child_attrs
                        elif isinstance(ret, list):
                            ret.append(child_attrs)
                        else:
                            ret = [ret, child_attrs] if child_attrs is not None else [ret]
        
        return ret

    def getAllDownByType(self, type_class):
        """Get all objects of a specific type in the tree rooted at this node."""
        ret = []
        visited = set()  # Track visited nodes to avoid duplicates
        
        def _collect_recursive(node):
            # Avoid infinite loops and duplicates
            if id(node) in visited:
                return
            visited.add(id(node))
            
            # Check if this node is of the requested type
            if isinstance(node, type_class):
                ret.append(node)

            # Recursively check children
            if hasattr(node, 'children') and node.children:
                for child in node.children:
                    if isinstance(child, TreeNode):
                        _collect_recursive(child)
        
        _collect_recursive(self)
        return ret

    def getDescendantById(self, target_id):
        """Get a direct descendant by ID within this node's immediate children."""
        if not hasattr(self, 'children') or not self.children:
            return None
            
        for child in self.children:
            if hasattr(child, '_id') and child._id == target_id:
                return child
                
        # Search recursively in children
        for child in self.children:
            if hasattr(child, 'getDescendantById'):
                result = child.getDescendantById(target_id)
                if result is not None:
                    return result
                    
        return None

    def getDescendantFirstById(self, target_id):
        """Get any descendant by ID within this tree, searching all levels."""
        # First try direct descendants
        result = self.getDescendantById(target_id)
        if result is not None:
            return result
            
        # Then search in any specialized child collections (to be overridden by subclasses)
        return None
