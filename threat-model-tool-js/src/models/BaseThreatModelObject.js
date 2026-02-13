import TreeNode from '../utils/TreeNode.js';

class BaseThreatModelObject extends TreeNode {
    constructor(dictData = {}, parent = null) {
        super(dictData, parent);
        this.originDict = dictData;
        this._description = "";
        this.isReference = false;

        // Set attributes from dictionary
        for (const [key, value] of Object.entries(dictData)) {
            if (key !== "ID" && key !== "children" && key !== "parent") {
                // Check if the property has a setter or is not a getter
                const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(this), key);
                if (!descriptor || descriptor.set || descriptor.writable) {
                     this[key] = value;
                }
            }
        }
    }
    
    get id() {
        return this.originDict.ID;
    }

    get description() {
        return this._description;
    }

    set description(value) {
        this._description = value;
    }

    matchesVersion(appliesToVersion) {
        if (!this.versionsFilter) {
            return true;
        }
        return this.versionsFilter.includes(appliesToVersion);
    }

    filterOutForPublicOrVersions(publicFlag, dict) {
        return this.filterOutForPublic(publicFlag, dict) || this.filterOutForVersions(dict);
    }

    filterOutForVersions(dict) {
        return 'appliesToVersions' in dict && !this.matchesVersion(dict['appliesToVersions']);
    }

    filterOutForPublic(publicFlag, dict) {
        return publicFlag && 'public' in dict && dict['public'] === false;
    }

    update(dict) {
        try {
            Object.assign(this.originDict, dict);
        } catch {
            throw new Error(`originDict not set by the object parser in: ${this.id}`);
        }
    }

    get versionsFilter() {
        if (!this._versionsFilter) {
            return this.parent ? this.parent.versionsFilter : null;
        }
        return this._versionsFilter;
    }

    get title() {
        return this.description ? this.description.substring(0, 50) + "[...]" : "No title";
    }

    set title(value) {
        this._title = value;
    }

    printAsText() {
        return `\nID: ${this.id} \nDescription: ${this.description}`;
    }

    getThreatModel() {
        if (this.constructor.name === 'ThreatModel') {
            return this;
        } else if (!this.parent) {
            return null;
        } else {
            return this.parent.getThreatModel();
        }
    }

    getFileAndLineErrorMessage() {
        const threatModel = this.getThreatModel();
        const filename = threatModel ? threatModel.fileName : "unknown";
        return ` (file: "${filename}")`;
    }
}

export default BaseThreatModelObject;