// complianceMetricResolve — small helper used by CompliancePage to
// pull a numeric value out of /api/stats or /api/security via the
// dotted-`path` the ComplianceMetric carries. Kept separate so it can
// be unit-tested without the React renderer.
//
// Path semantics:
//   - dots split into segments
//   - each segment is a property lookup (string keys; numeric keys are
//     OK because JS object keys are always strings under the hood)
//   - traversal stops at the first non-object, returning undefined for
//     a missing segment so a stale UI does not throw on a partial
//     response

export function resolveMetricPath(obj: unknown, path: string): number | undefined {
  if (obj == null) return undefined
  let cur: unknown = obj
  for (const seg of path.split('.')) {
    if (typeof cur !== 'object' || cur === null) return undefined
    cur = (cur as Record<string, unknown>)[seg]
    if (cur === undefined) return undefined
  }
  return typeof cur === 'number' ? cur : undefined
}
