// Package attackpath implements a local attack path analysis service.
//
// It builds an attack graph from an asset inventory, connectivity rules and
// vulnerabilities, derives the set of externally reachable assets as a
// least fixed point (cycles always terminate), enumerates simple attack
// paths to critical assets, scores path and aggregate asset risk, supports
// incremental updates with results identical to a full rebuild, answers
// constrained path queries, and serves concurrent readers from immutable
// snapshots with durable snapshot+WAL persistence and crash recovery.
package attackpath
