# Stage 4 Query Grammar Notes (design record, do not implement yet)

Decisions recorded during Stage 1.5 for the future Stage 4 query bar. Nothing
here is implemented now: Stage 1.5 filtering is dropdowns and free-text over
the cached pool, with no query language. These notes exist so the Stage 4
grammar is settled before it is built.

## Pipe structure (four parts)

```
TIMEFRAME | SENSOR_SELECTOR | EVENT_TYPE | FILTERS
```

- **TIMEFRAME**: the time window, anchored to the frozen scenario clock (the
  Stage 1.5 time presets already establish this: never wall time).
- **SENSOR_SELECTOR**: which sensor/source or host the query targets.
- **EVENT_TYPE**: the event class to match.
- **FILTERS**: field predicates combined with the operators below.

## Operators

- `contains`, `not contains`
- `==`, `!=`
- `and`, `or`

## Quote semantics

- Double quotes: case-insensitive match. `"Powershell"` matches `powershell`.
- Single quotes: case-sensitive match. `'PowerShell'` matches only that casing.

## Deferred out of Stage 4 v1

- Projection (selecting/reshaping output columns).
- GROUP BY aggregation.

Both are explicitly out of the first Stage 4 query engine; revisit only after
the core grammar ships.

## Implementation reminders (from the plan, for whoever builds Stage 4)

- Proper tokenizer and parser, not ad hoc regex.
- Runs against the scenario's full event pool (attack plus noise), all
  post-substitution values.
- Deterministic: identical queries return identical results.
- Unit tests covering grammar edge cases before wiring to the UI.
