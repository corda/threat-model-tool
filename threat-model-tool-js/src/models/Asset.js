import BaseThreatModelObject from './BaseThreatModelObject.js';

class Asset extends BaseThreatModelObject {
    constructor(dictData, parent) {
        super(dictData, parent);
        if (!dictData || (!dictData.type && !dictData.ID)) {
            throw new Error(`Asset must have a 'type' or 'ID' property`);
        }

        this.type = dictData.type;
        this.inScope = dictData.inScope !== undefined ? dictData.inScope : true;
        this.properties = dictData.properties || {};
    }

    propertiesHTML() {
        let html = "<ul>";
        for (const [key, value] of Object.entries(this.properties)) {
            html += `<li style='margin: 0px 0;'><b>${key}:</b> &nbsp;${value}</li>`;
        }
        return html + "</ul>";
    }
}

export default Asset;
