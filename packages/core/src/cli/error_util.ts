// CLI error helpers

export function errMessage(err: unknown): string {
    if (err instanceof Error) return err.message;
    if (typeof err === 'string') return err;
    return String(err);
}

export function errCode(err: unknown): string | undefined {
    if (err && typeof err === 'object' && 'code' in err) {
        const code = (err as { code: unknown }).code;
        return typeof code === 'string' ? code : undefined;
    }
    return undefined;
}
