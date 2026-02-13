class TreeNode {
    constructor(data, parent = null) {
        this.data = data;
        this.parent = parent;
        this.children = new Set();
        
        if (parent) {
            parent.addChild(this);
        }
    }

    addChild(child) {
        this.children.add(child);
    }

    removeChild(child) {
        this.children.delete(child);
    }

    getRoot() {
        let current = this;
        while (current.parent) {
            current = current.parent;
        }
        return current;
    }

    getDescendantById(id) {
        for (const child of this.children) {
            if (child.data.ID === id) {
                return child;
            }
            const found = child.getDescendantById(id);
            if (found) {
                return found;
            }
        }
        return null;
    }

    getAllDown(type) {
        const results = [];
        for (const child of this.children) {
            if (child instanceof type) {
                results.push(child);
            }
            results.push(...child.getAllDown(type));
        }
        return results;
    }

    isRoot() {
        return this.parent === null;
    }
}

export default TreeNode;