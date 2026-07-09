# Stack pack: node — api-contract
extends: core/skills/api-contract/SKILL.md

## Stack-specific signals
- `JSON.stringify` of `BigInt`/`Date`/`Map`/`Set` producing wrong/lossy output (`BigInt` throws; `Date` serializes to ISO string inconsistently; `Map`/`Set` become `{}`).
- Response field renamed/removed without versioning, breaking clients.
- Status codes that don't match semantics (200 for created-with-side-effects vs 201; 200 for errors).
- `any`/casts on request payloads bypassing validation at the boundary.
- Inconsistent content-type / content negotiation across endpoints.
- Optional vs required mismatches between the route handler and the documented/openapi schema.

## Stack-specific remedies
- Serialize explicitly at the edge (convert `Date`/`BigInt`/`Decimal` to a defined wire format).
- Version breaking changes (URL/header); keep aliases during migration.
- Align status codes with REST semantics; type the request/response with a shared schema.

## Stack-specific severity guidance
- `JSON.stringify` crash on `BigInt` on a real response path: High.
- Renamed/removed response field with no versioning: High.
- `any` on a request boundary: Medium/High depending on downstream use.
