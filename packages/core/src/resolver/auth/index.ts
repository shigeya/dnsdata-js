// Barrel for the auth resolver. Importing this module guarantees
// that [AuthClient.prototype.resolve] is installed (see resolve.ts).

import './resolve';

export * from './client';
export * from './errors';
