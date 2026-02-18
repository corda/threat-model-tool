import TreeNode from '../utils/TreeNode.js';
import type { ThreatModelObjectType } from '../types.js';

export default class BaseThreatModelObject extends TreeNode {
    originDict: Record<string, any>;
    protected _id: string;
    protected _description: string;
    isReference: boolean;
    protected _title?: string;
    protected _versionsFilter?: string[] | null;

    constructor(dictData: Record<string, any> = {}, parent: BaseThreatModelObject | null = null) {
        super(dictData, parent);
        this.originDict = dictData;
        this._id = dictData.ID;
        this._description = dictData.description || "";
        this.isReference = false;

        // Set attributes from dictionary
        for (const [key, value] of Object.entries(dictData)) {
            if (key !== "ID" && key !== "children" && key !== "parent" && key !== "threats" && key !== "scope") {
                // Check if the property has a setter or is not a getter
                const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(this), key);
                if (!descriptor || descriptor.set || descriptor.writable !== false) {
                    (this as any)[key] = value;
                }
            }
        }
    }
    
    get id(): string {
        return this._id;
    }

    /**
     * Get the full hierarchical ID: parent.id + "." + self._id
     * Matches Python tree_node's id property.
     */
    getHierarchicalId(): string {
        if (this.parent && (this.parent as any).getHierarchicalId) {
            return `${(this.parent as any).getHierarchicalId()}.${this._id}`;
        }
        return this._id;
    }

    /**
     * Get the anchor part of the ID (excluding root hierarchy).
     * Matches Python tree_node: strips everything up to and including the first dot
     * from the hierarchical ID.
     * 
     * Examples:
     *   FullFeature.THREAT_SQL_INJECTION → THREAT_SQL_INJECTION
     *   FullFeature.SubComponent.SUB_THREAT → SubComponent.SUB_THREAT
     *   FullFeature (root, no dot) → FullFeature
     */
    get anchor(): string {
        const fullId = this.getHierarchicalId();
        const dotIndex = fullId.indexOf('.');
        if (dotIndex >= 0) {
            return fullId.substring(dotIndex + 1);
        }
        return fullId;
    }

    get description(): string {
        return this._description;
    }

    set description(value: string) {
        this._description = value;
    }

    matchesVersion(appliesToVersion: string): boolean {
        if (!this.versionsFilter) {
            return true;
        }
        return this.versionsFilter.includes(appliesToVersion);
    }

    filterOutForPublicOrVersions(publicFlag: boolean, dict: Record<string, any>): boolean {
        return this.filterOutForPublic(publicFlag, dict) || this.filterOutForVersions(dict);
    }

    filterOutForVersions(dict: Record<string, any>): boolean {
        return 'appliesToVersions' in dict && !this.matchesVersion(dict['appliesToVersions']);
    }

    filterOutForPublic(publicFlag: boolean, dict: Record<string, any>): boolean {
        return publicFlag && 'public' in dict && dict['public'] === false;
    }

    update(dict: Record<string, any>): void {
        try {
            Object.assign(this.originDict, dict);
        } catch {
            throw new Error(`originDict not set by the object parser in: ${this.id}`);
        }
    }

    get versionsFilter(): string[] | null {
        if (!this._versionsFilter) {
            return this.parent ? (this.parent as BaseThreatModelObject).versionsFilter : null;
        }
        return this._versionsFilter;
    }

    get title(): string {
        if (this._title) {
            return this._title;
        }
        return this.description ? this.description.substring(0, 50) + "[...]" : "No title";
    }

    set title(value: string) {
        this._title = value;
    }

    printAsText(): string {
        return `\nID: ${this.id} \nDescription: ${this.description}`;
    }

    getThreatModel(): any {
        if (this.constructor.name === 'ThreatModel') {
            return this;
        } else if (!this.parent) {
            return null;
        } else {
            return (this.parent as BaseThreatModelObject).getThreatModel();
        }
    }

    getFileAndLineErrorMessage(): string {
        const threatModel = this.getThreatModel();
        const filename = threatModel ? threatModel.fileName : "unknown";
        return ` (file: "${filename}")`;
    }
}
