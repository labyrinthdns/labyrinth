// Ambient module declaration for jest-axe (no .d.ts shipped upstream).
declare module 'jest-axe' {
  import { AxeResults } from 'axe-core'

  export interface JestAxeOptions {
    globalOptions?: { disableOtherChecks?: boolean }
    rules?: Record<string, { enabled: boolean }>
  }

  export function axe(
    html: Element | Document | string,
    options?: JestAxeOptions,
  ): Promise<AxeResults>

  export const toHaveNoViolations: {
    toHaveNoViolations(results: AxeResults & { toolOptions?: { impactLevels?: string[] } }): {
      actual: import('axe-core').Result[]
      message: () => string
      pass: boolean
    }
  }
}
