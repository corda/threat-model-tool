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
                this._scores = {
                    base: all.base?.score ?? 0,
                    temporal: all.temporal?.score ?? 0,
                    environmental: all.environmental?.score ?? 0,
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
            return [this._scores.base, this._scores.temporal, this._scores.environmental];
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
     */
    getSmartScoreDesc(): string {
        if (this.isTodo()) return 'TODO CVSS';
        const idx = this.getSmartScoreIndex();
        const score = this.scores()[idx];
        const severity = this.severities()[idx];
        return `${score} (${severity})`;
    }

    getSmartScoreVal(): number {
        if (this.isTodo()) return 0;
        return this.scores()[this.getSmartScoreIndex()];
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
