---
"ssh-mcp": patch
---

Index `roleBindings` on a null-prototype object ([#172](https://github.com/tufantunc/ssh-mcp/issues/172)).

A role name is a free string, and `mergePolicyRules` assigns `roleBindings[role]`. On a plain object that assignment is not always a key: for `__proto__` it invokes the prototype setter instead. Measured, the effect was not global — `Object.prototype` stayed clean — but the object's own prototype became the operator's tier map, after which `roleBindings.prod` resolved through the chain as though `prod` were a role.

Not reachable: the config schema rejects `__proto__`, `constructor` and `prototype` as role or tier names before the engine sees a config, and the policy engine's own coherence check refuses a role no profile uses. What makes it worth closing anyway is that the first of those guards is the one zod 4 silently disabled, rebuilt in 2.5.0 — the authorization engine should not depend on a check that has already regressed once.

`DEFAULT_RULES.roleBindings` gets the same treatment, because `mergePolicyRules` returns it unchanged when there is no `[policy]` section, which is the commonest path. That also removes a second case needing no config at all: on a plain object `roleBindings['toString']` returned a function, so a profile whose role was named after an `Object.prototype` member found a truthy binding. It failed closed — the coherence check still refused it and evaluation floored at read-only — but by a different route than an unknown role, for no reason a reader could see.

No behaviour change for any valid configuration. Reported by [@allenwu-blip](https://github.com/allenwu-blip) using [mcpaudit](https://github.com/allenwu-blip/mcpaudit).
