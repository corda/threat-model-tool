export function parseFlag(args: string[], flag: string): boolean {
    return args.includes(`--${flag}`);
}

export function parseOption(args: string[], flag: string): string | undefined {
    const idx = args.indexOf(`--${flag}`);
    if (idx !== -1 && idx + 1 < args.length && !args[idx + 1].startsWith('--')) {
        return args[idx + 1];
    }
    return undefined;
}

export function parseMultiOption(args: string[], flag: string): string[] {
    const values: string[] = [];

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        const longFlag = `--${flag}`;
        const eqPrefix = `${longFlag}=`;

        if (arg === longFlag && i + 1 < args.length) {
            values.push(args[++i]);
        } else if (arg.startsWith(eqPrefix)) {
            values.push(arg.slice(eqPrefix.length));
        }
    }

    return values
        .flatMap(value => value.split(','))
        .map(value => value.trim())
        .filter(Boolean);
}
