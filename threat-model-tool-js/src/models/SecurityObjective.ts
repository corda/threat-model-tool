import BaseThreatModelObject from './BaseThreatModelObject.js';
import REFID from './REFID.js';

export default class SecurityObjective extends BaseThreatModelObject {
    contributesTo: REFID[] = [];
    scope: any;
    group: string;
    priority: string = "High";
    inScope: boolean = true;
    private _treeImage: boolean = true;

    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
        this.scope = parent;
        this.group = dictData.group || "General";

        // Handle contributesTo references
        if (dictData.contributesTo) {
            for (const dict2 of dictData.contributesTo) {
                if (dict2.REFID) {
                    this.contributesTo.push(new REFID(dict2, this));
                }
            }
        }
    }

    get treeImage(): boolean {
        // Check if there are any threats impacting this objective
        const root = this.getThreatModel() as any;
        if (!root) return false;
        
        const threats = root.getThreatsByFullyMitigated ? root.getThreatsByFullyMitigated(false) : [];
        threats.push(...(root.getThreatsByFullyMitigated ? root.getThreatsByFullyMitigated(true) : []));
        
        for (const threat of threats) {
            if (threat.impactedSecObjs) {
                for (const impactedSecObj of threat.impactedSecObjs) {
                    if (impactedSecObj.REFIDValue === this.id) {
                        return this._treeImage;
                    }
                }
            }
        }
        return false;
    }

    set treeImage(value: boolean) {
        this._treeImage = value;
    }

    /**
     * Generate markdown link with anchor for impact reference
     */
    linkedImpactMDText(): string {
        return `<code><a href="#${this.anchor}">${this.id}</a></code>`;
    }

    /**
     * Generate markdown text for contributesTo relationship
     */
    contributedToMDText(): string {
        return `<code><a href="#${this.anchor}">${this.id}</a></code> *(${this.title})*`;
    }

    printAsText(): string {
        return `\nID: ${this.id} \nDescription: ${this.description}`;
    }

    shortText(): string {
        const firstPara = this.description.split("\n")[0];
        return `*${this.id}*\n(${firstPara})`;
    }
}
