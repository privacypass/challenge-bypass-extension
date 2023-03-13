export interface StorageAPI {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
}

export class LocalStorage implements StorageAPI {
    constructor(private prefix: string) {}

    getItem(key: string): string | null {
        return window.localStorage.getItem(`${this.prefix}-${key}`);
    }

    setItem(key: string, value: string): void {
        window.localStorage.setItem(`${this.prefix}-${key}`, value);
    }
}
