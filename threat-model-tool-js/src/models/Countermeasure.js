import BaseThreatModelObject from './BaseThreatModelObject.js';

class Countermeasure extends BaseThreatModelObject {
    constructor(dictData, threat) {
        super(dictData, threat);
        this.threat = threat;

        const requiredKeys = ["inPlace", "public", "description", "title"];
        for (const key of requiredKeys) {
            if (!(key in dictData) || dictData[key] === null) {
                // throw new Error(`Countermeasure needs a '${key}' attribute`);
            }
            this[key] = dictData[key];
        }

        this.operational = false;
        this._operator = "UNDEFINED";
    }

    RAGStyle() {
        return this.inPlace ? "countermeasureIP" : "countermeasureNIP";
    }

    get operator() {
        return this._operator;
    }

    set operator(value) {
        if (value) {
            this._operator = value;
        }
    }
}

export default Countermeasure;
