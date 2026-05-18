// Barrel for the DoH client. Importing this module guarantees that
// [DoHClient.prototype.resolve] is installed (see resolve.ts).

import './resolve';

export * from './client';
export * from './errors';
