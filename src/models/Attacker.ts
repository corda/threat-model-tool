// Attacker.ts
import BaseThreatModelObject from './BaseThreatModelObject.js';

export default class Attacker extends BaseThreatModelObject {
    inScope: boolean = true;

    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
        this.inScope = dictData.inScope !== undefined ? dictData.inScope : true;
    }
}
