## 2024-05-22 - [SQLAlchemy LargeBinary Deferral]
**Learning:** The codebase stores full PDF reports (`LargeBinary`) directly in analysis tables (`BreachAnalysis`, `SecurityAnalysis`, etc.). List views were fetching these massive blobs by default.
**Action:** When querying models with `LargeBinary` columns for list/summary views, ALWAYS use `query.options(defer(Model.column))` to avoid loading the binary data.
