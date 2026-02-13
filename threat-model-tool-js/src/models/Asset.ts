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
        let html = "<ul>";
        for (const [key, value] of Object.entries(this.properties)) {
            html += `<li style='margin: 0px 0;'><b>${key}:</b> &nbsp;${value}</li>`;
        }
        return html + "</ul>";
    }
}
