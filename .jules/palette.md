## 2025-05-15 - Accessible Radio Buttons in Flask Templates
**Learning:** Standard `display: none` on radio inputs (common in custom UI) completely breaks keyboard navigation.
**Action:** Use the "visually hidden" pattern (opacity 0, absolute position) instead, and ensure the adjacent label has a visible focus state.
