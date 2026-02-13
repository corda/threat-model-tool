export default class TreeNode {
    data: Record<string, any>;
    parent: TreeNode | null;
    children: Set<TreeNode>;

    constructor(data: Record<string, any>, parent: TreeNode | null = null) {
        this.data = data;
        this.parent = parent;
        this.children = new Set();
        
        if (parent) {
            parent.addChild(this);
        }
    }

    addChild(child: TreeNode): void {
        this.children.add(child);
    }

    removeChild(child: TreeNode): void {
        this.children.delete(child);
    }

    getRoot(): TreeNode {
        let current: TreeNode = this;
        while (current.parent) {
            current = current.parent;
        }
        return current;
    }

    getDescendantById(id: string): TreeNode | null {
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

    getAllDown<T extends TreeNode>(type: new (...args: any[]) => T): T[] {
        const results: T[] = [];
        for (const child of this.children) {
            if (child instanceof type) {
                results.push(child);
            }
            results.push(...child.getAllDown(type));
        }
        return results;
    }

    isRoot(): boolean {
        return this.parent === null;
    }
}
