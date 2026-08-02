import { defineConfig } from 'vitest/config';

const quietReporterEnabled = process.env.MCPORTER_TEST_REPORTER === 'quiet';

const quietReporterOptions = quietReporterEnabled
  ? {
      reporters: ['dot'],
      silent: 'passed-only' as const,
    }
  : {};

export default defineConfig({
  test: {
    // Quiet mode hides console output for passing tests so CLI fixture logs
    // (e.g., the full `mcporter list` banners) don't overwhelm the reporter.
    ...quietReporterOptions,
    // CLI-heavy suites import the full entrypoint in parallel and can exceed the
    // default 5s timeout under local load even when behavior is correct.
    testTimeout: 10_000,
    // Agent worktrees under .claude/worktrees contain full repo copies; without
    // this exclude a root-level run also collects every worktree's test suite.
    exclude: ['**/node_modules/**', '**/dist/**', '**/.claude/**'],
  },
});
