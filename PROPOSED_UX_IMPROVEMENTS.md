# Additional Unlisted UX/DX Recommendations

During the remediation of the primary heuristic evaluation, several additional opportunities for friction reduction and DX enhancement were identified. These changes have not been implemented yet to avoid unintended behavioral alterations without approval.

## 1. Focus Management on State Mutations (Accessibility)
*   **Observation:** When a user initiates a search or an AI generation task (e.g., in `web/study_plan.tsx`), the screen changes, but keyboard focus remains on the triggering button or drops entirely.
*   **Recommendation:** Use a React `useRef` to programmatically pull keyboard focus to the resulting content container or error summary block as soon as the asynchronous operation completes. This prevents screen reader users from having to tab entirely through the layout again.

## 2. API Response Wrapper Normalization (DX)
*   **Observation:** The backend error mapper relies on HTTP status codes to differentiate success vs error. While standard, many modern SPA clients prefer a standardized envelope structure.
*   **Recommendation:** Wrap all JSON responses in an envelope, e.g., `{"success": false, "error": {...}}` or `{"success": true, "data": {...}}`. This prevents frontend state management logic from splitting wildly between Axios `try/catch` and standard payload parsing, reducing cognitive load on the client engineering team.

## 3. Mobile "Offline" or "Sync Dropped" State Banners (UX)
*   **Observation:** The Real-time Canvas (Zoom Room Sync) documentation notes that failure falls back to a 10s poll.
*   **Recommendation:** In `mobile/scripture_reader.tsx`, we should explicitly model an offline/degraded state component (a non-intrusive yellow banner at the top) that clearly communicates "Live sync disconnected - Reconnecting...".

## 4. Debounce and Rate-Limit Transparency
*   **Observation:** Global scripture search relies on debouncing.
*   **Recommendation:** Expose the `Retry-After` header explicitly if the user triggers rate limiting on searches, and map that header to the frontend to visually disable the search button with a countdown timer, rather than failing silently or spinning indefinitely.
