import CVSS from 'cvss';

export class TMCVSS {
    vector: string;
    private _base: string | number;
    private _scores: { base: number; temporal: number; environmental: number } | null = null;

    constructor(vectorOrDict: string | Record<string, any>) {
        if (typeof vectorOrDict === 'string') {
            this.vector = vectorOrDict;
            this._base = '';
        } else {
            this.vector = vectorOrDict.vector || '';
            this._base = vectorOrDict.base ?? '';
        }

        // Compute scores from vector
        if (this.vector && !this.isTodo()) {
            try {
                const normalizedVector = this.normalizeVector(this.vector);
                const all = CVSS.getAll(normalizedVector);
                const readScore = (value: any): number => {
                    if (typeof value === 'number') return value;
                    return Number(value?.score ?? 0);
                };
                const base = readScore((all as any).base);
                const temporal = readScore((all as any).temporal);
                const environmental = readScore((all as any).environmental);
                this._scores = {
                    base: Number.isFinite(base) ? base : 0,
                    temporal: Number.isFinite(temporal) ? temporal : 0,
                    environmental: Number.isFinite(environmental) ? environmental : 0,
                };
            } catch {
                this._scores = null;
            }
        }
    }

    /**
     * Normalize a CVSS vector so the `cvss` npm package can parse it.
     * The package requires `CVSS:3.0/...` prefix; vectors with `CVSS:3.1/` must be adjusted.
     */
    private normalizeVector(vector: string): string {
        if (vector.startsWith('CVSS:3.1/')) {
            return 'CVSS:3.0/' + vector.slice('CVSS:3.1/'.length);
        }
        if (!vector.startsWith('CVSS:')) {
            return 'CVSS:3.0/' + vector;
        }
        return vector;
    }

    isTodo(): boolean {
        return !this.vector || this.vector.trim() === '' || String(this._base).includes('TODO');
    }

    scores(): [number, number, number] {
        if (this._scores) {
            const base = Number.isFinite(this._scores.base) ? this._scores.base : 0;
            const temporal = Number.isFinite(this._scores.temporal) ? this._scores.temporal : 0;
            const environmental = Number.isFinite(this._scores.environmental) ? this._scores.environmental : 0;
            return [base, temporal, environmental];
        }
        return [0, 0, 0];
    }

    severities(): [string, string, string] {
        const [base, temporal, environmental] = this.scores();
        return [
            this.scoreToSeverity(base),
            this.scoreToSeverity(temporal),
            this.scoreToSeverity(environmental),
        ];
    }

    private scoreToSeverity(score: number): string {
        if (score === 0) return 'None';
        if (score <= 3.9) return 'Low';
        if (score <= 6.9) return 'Medium';
        if (score <= 8.9) return 'High';
        return 'Critical';
    }

    /**
     * Return the most relevant score index (base, temporal, or environmental)
     * Matches Python TMCVSS.getSmartScoreIndex()
     */
    getSmartScoreIndex(): number {
        const [base, temporal, environmental] = this.scores();
        if (base === temporal && base === environmental) return 0;
        if (base === temporal && base !== environmental) return 2;
        if (base !== temporal && temporal === environmental) return 1;
        return [temporal, environmental].indexOf(Math.max(temporal, environmental)) + 1;
    }

    static readonly scoresNames = ['Base score', 'Temporal score', 'Environmental score'] as const;

    /**
     * Return the type label of the most relevant score.
     * E.g. "Base score", "Temporal score"
     */
    getSmartScoreType(): string {
        return TMCVSS.scoresNames[this.getSmartScoreIndex()];
    }

    /**
     * Return score description matching Python: "9.8 (Critical)"
     * If TODO, returns "TODO CVSS"
     * Note: Python floats format with decimal (10.0), so we match that
     */
    getSmartScoreDesc(): string {
        if (this.isTodo()) return 'TODO CVSS';
        const idx = this.getSmartScoreIndex();
        const rawScore = this.scores()[idx];
        const score = Number.isFinite(rawScore) ? rawScore : 0;
        const severity = this.severities()[idx];
        // Format score to always show decimal like Python (10.0 not 10)
        const scoreStr = Number.isInteger(score) ? score.toFixed(1) : String(score);
        return `${scoreStr} (${severity})`;
    }

    getSmartScoreVal(): number {
        if (this.isTodo()) return 0;
        const value = this.scores()[this.getSmartScoreIndex()];
        return Number.isFinite(value) ? value : 0;
    }

    getSmartScoreColor(): string {
        if (this.isTodo()) return 'gray';
        const score = this.getSmartScoreVal();
        if (score === 0) return '#53aa33';
        if (score <= 3.9) return '#ffcb0d';
        if (score <= 6.9) return '#f9a009';
        if (score <= 8.9) return '#df3d03';
        if (score <= 10) return '#cc0500';
        return 'gray';
    }

    getSmartScoreSeverity(): string {
        if (this.isTodo()) return 'TODO CVSS';
        return this.severities()[this.getSmartScoreIndex()];
    }

    /**
     * Return the vector string without the CVSS:3.x/ prefix, for display.
     */
    clean_vector(): string {
        if (!this.vector) return '';
        return this.vector;
    }
}
