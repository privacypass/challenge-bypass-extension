export interface Storage {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
}

export class LocalStorage implements Storage {
    private prefix: string;

    constructor(prefix: string) {
        this.prefix = prefix;
    }

    getItem(key: string): string | null {
        return window.localStorage.getItem(`${this.prefix}-${key}`);
    }

    setItem(key: string, value: string): void {
        window.localStorage.setItem(`${this.prefix}-${key}`, value);
    }
}

export function generatePrefixFromID(id: number): string {
    return 'id-' + id;
}

export function clearAllPasses(): void {
    window.localStorage.clear();
}
