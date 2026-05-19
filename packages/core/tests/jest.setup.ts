// Jest setup file (referenced from jest.config.ts `setupFiles`).
//
// P8 made RR handler registration opt-in. The test suite assumes
// every bundled handler is wired up — re-creating that expectation
// here keeps each spec from having to remember the registration
// dance.
import { registerAllHandlers } from '../src/index';

registerAllHandlers();
