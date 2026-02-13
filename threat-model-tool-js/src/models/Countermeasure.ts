import BaseThreatModelObject from './BaseThreatModelObject.js';

export default class Countermeasure extends BaseThreatModelObject {
    threat: any;
    inPlace?: boolean;
    public?: boolean;
    operational: boolean;
    private _operator: string;

    constructor(dictData: Record<string, any>, threat: any) {
        super(dictData, threat);
        this.threat = threat;
        this.operational = dictData.operational || false;
        this._operator = "UNDEFINED";

        const requiredKeys = ["inPlace", "public", "description", "title"];
        for (const key of requiredKeys) {
            if (!(key in dictData) || dictData[key] === null) {
                throw new Error(`Countermeasure needs a '${key}' attribute${this.getFileAndLineErrorMessage()}`);
            }
        }
    }

    printAsText(): string {
        return `\nID: ${this.id} \nDescription: ${this.description}`;
    }

    /**
     * Return RAG (Red/Amber/Green) style class name
     */
    RAGStyle(): string {
        return this.inPlace ? "countermeasureIP" : "countermeasureNIP";
    }

    /**
     * Return colors for PlantUML diagrams
     */
    statusColors(): { border: string; fill: string } {
        const inPlace = { border: '#82B366', fill: '#D5E8D4' };
        const notInPlace = { border: '#D6B656', fill: '#FFF2CC' };
        return this.inPlace ? inPlace : notInPlace;
    }

    get operator(): string {
        return this._operator;
    }

    set operator(value: string) {
        if (value) {
            this._operator = value;
        }
    }
}
