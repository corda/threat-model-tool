/**
 * HeadingNumberer - Singleton to track hierarchical heading numbers
 * Maintains state like 1, 1.1, 1.1.1, etc.
 */
export class HeadingNumberer {
    private static _instance: HeadingNumberer | null = null;
    private static _enabled: boolean = true;
    private static hierarchicalCounterLimit: number = 4;

    private counters: number[] = [];

    private constructor() {
        this.reset();
    }

    static getInstance(): HeadingNumberer {
        if (!HeadingNumberer._instance) {
            HeadingNumberer._instance = new HeadingNumberer();
        }
        return HeadingNumberer._instance;
    }

    reset(): void {
        this.counters = [0];
    }

    /**
     * Get the number for the given heading level
     * Returns empty string if disabled or level > limit
     */
    getNumber(level: number): string {
        if (!HeadingNumberer._enabled) {
            return "";
        }

        if (level > HeadingNumberer.hierarchicalCounterLimit) {
            return "";
        }

        // Adjust counters array to match level
        while (this.counters.length < level) {
            this.counters.push(0);
        }
        while (this.counters.length > level) {
            this.counters.pop();
        }

        // Increment current level
        this.counters[this.counters.length - 1]++;

        // Return formatted number (e.g., "1.2.3")
        return this.counters.join('.');
    }

    static enable(): void {
        HeadingNumberer._enabled = true;
    }

    static disable(): void {
        HeadingNumberer._enabled = false;
    }

    static isEnabled(): boolean {
        return HeadingNumberer._enabled;
    }

    static setLimit(limit: number): void {
        HeadingNumberer.hierarchicalCounterLimit = limit;
    }
}

// Global helper functions
export function enableHeadingNumbering(): void {
    HeadingNumberer.enable();
}

export function disableHeadingNumbering(): void {
    HeadingNumberer.disable();
}

export function resetHeadingNumbers(): void {
    HeadingNumberer.getInstance().reset();
}

export function isHeadingNumberingEnabled(): boolean {
    return HeadingNumberer.isEnabled();
}
