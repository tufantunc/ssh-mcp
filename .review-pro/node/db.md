# Stack pack: node — db
extends: core/skills/db/SKILL.md

## Stack-specific signals
- String-interpolated SQL (`"... WHERE id = " + req.params.id`) instead of parameterized queries → SQL injection (defer severity to security).
- ORM/query-builder calls inside a loop (`for (x of items) await prisma.x.find(x.id)`) → N+1.
- Missing transaction around multi-step writes (`db.users.create` then `db.orders.create` without a tx) → partial state.
- Migrations written as plain SQL with no `up`/`down`, or `down` that can't reverse the change.
- Connection pool misconfigured (unbounded, or a new client per request) → pool exhaustion.
- Raw `UPDATE`/`DELETE` migrations with no `WHERE` / no safeguard → mass data change.
- BigInt/Decimal read back through JSON without serialization handling → precision loss.

## Stack-specific remedies
- Always parameterize; prefer the query builder/ORM over raw SQL.
- Batch fetches (`findMany`, `IN (...)`); wrap multi-step writes in a transaction.
- Write reversible migrations; back up/verify before destructive steps.
- Reuse a configured pool; bound concurrency.

## Stack-specific severity guidance
- String-interpolated SQL: Critical (hand to `security` for severity).
- N+1 query loop: High (hand to `performance` for impact).
- Non-atomic multi-step write: High.
