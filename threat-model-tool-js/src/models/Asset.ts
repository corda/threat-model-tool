import BaseThreatModelObject from './BaseThreatModelObject.js';

export default class Asset extends BaseThreatModelObject {
    type?: string;
    inScope: boolean;
    properties: Record<string, any>;

    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
        if (!dictData || (!dictData.type && !dictData.ID)) {
            throw new Error(`Asset must have a 'type' or 'ID' property`);
        }

        this.type = dictData.type;
        this.inScope = dictData.inScope !== undefined ? dictData.inScope : true;
        this.properties = dictData.properties || {};
    }

    propertiesHTML(): string {
        // Python returns "" if no properties attribute exists
        // Since TS always sets properties (default {}), check if it's empty or missing from original dict
        if (!this.originDict.properties) {
            return "";
        }
        // Python uses dict.items() with a try/except that fails silently for arrays.
        // If properties is an array (not a dict with named keys), return empty like Python.
        if (Array.isArray(this.properties)) {
            return "<ul></ul>";
        }
        let html = "<ul>";
        for (const [key, value] of Object.entries(this.properties)) {
            // Handle object values by JSON stringifying them
            let displayValue = value;
            if (typeof value === 'object' && value !== null) {
                displayValue = JSON.stringify(value);
            }
            html += `<li style='margin: 0px 0;'><b>${key}:</b> &nbsp;${displayValue}</li>`;
        }
        return html + "</ul>";
    }
}
