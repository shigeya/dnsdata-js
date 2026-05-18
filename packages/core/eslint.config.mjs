 // ESLint 9 flat config for @dnsdata/core
// https://eslint.org/docs/latest/use/configure/configuration-files

import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
    {
        ignores: ['dist/**', 'node_modules/**', 'coverage/**'],
    },
    ...tseslint.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2020,
            sourceType: 'module',
            globals: {
                ...globals.node,
                ...globals.jest,
            },
        },
        rules: {
            '@typescript-eslint/no-unused-vars': ['error', {
                argsIgnorePattern: '^_',
                varsIgnorePattern: '^_',
                caughtErrorsIgnorePattern: '^_',
            }],
        },
    },
    {
        // Test files: relax rules that are unavoidable in test scaffolding.
        // - no-explicit-any: needed for `null as any` constructor placeholders
        //   and `format: 'jwk' as any` for Node crypto JWK boundaries.
        // - no-require-imports: tests intentionally use late `require()` for
        //   modules whose registration side-effects must happen after setup.
        files: ['tests/**/*.ts'],
        rules: {
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-require-imports': 'off',
        },
    },
);
