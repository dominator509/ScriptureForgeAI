# Phase 2: Structural Accessibility (a11y) & Standards Compliance Report

## 1. Static Code Analysis (JSX/TSX Structural Constraints)

Upon deep inspection of the Next.js (`web/`) and React Native (`mobile/`) implementations, several severe structural accessibility violations were identified, largely stemming from incorrect usage of semantic HTML and missing ARIA properties.

### 1.1 Web Application Structural Violations
**Violation 1: Improper Interactive Elements (`<div onClick={...}>`)**
*   **File:** `web/dummy_component.tsx`, `web/study_plan.tsx`
*   **Issue:** The UI relies on `<div>` elements with `onClick` handlers for primary actions (e.g., "Generate Plan").
*   **Impact:**
    *   **Keyboard Accessibility:** `<div>` elements do not naturally receive focus via the `Tab` key. Keyboard-only users cannot navigate to or activate these buttons without a mouse.
    *   **Screen Readers:** Without a `role="button"` and `tabIndex={0}`, screen readers do not announce these elements as interactive buttons.
    *   **Activation:** Spacebar and Enter keys will not trigger the `onClick` event by default.
*   **Remediation:** Replace all `<div onClick={...}>` with semantic `<button type="button" onClick={...}>`.

**Violation 2: Missing Form Semantics & Labels**
*   **File:** `web/study_plan.tsx`
*   **Issue:** The input field (`<input type="text" placeholder="Topic" />`) lacks an associated `<label>` or `aria-label`.
*   **Impact:** Screen readers will only read the placeholder text, which is notoriously unreliable and disappears once the user begins typing, causing loss of context.
*   **Remediation:** Add `<label htmlFor="topic-input">Study Topic</label>` and assign `id="topic-input"` to the input.

**Violation 3: Unannounced Dynamic State Changes**
*   **File:** `web/study_plan.tsx`
*   **Issue:** When generating a study plan, the button text changes to "Generating...", but this state change is not broadcasted programmatically.
*   **Impact:** Visually impaired users are unaware that the system is processing the request.
*   **Remediation:** Implement an `aria-live="polite"` region to announce loading states, and use `aria-busy="true"` on the processing container.

### 1.2 Mobile Application Structural Violations (React Native)
**Violation 1: Missing Accessibility Labels and Traits**
*   **File:** `mobile/scripture_reader.tsx`
*   **Issue:** The `<TouchableOpacity>` does not have `accessibilityRole="button"` or an `accessibilityLabel`.
*   **Impact:** iOS VoiceOver and Android TalkBack may not correctly identify the interactable area as a button or provide context beyond reading the child text.
*   **Remediation:** Apply explicit accessibility props: `<TouchableOpacity accessibilityRole="button" accessibilityLabel="View Commentary for current verse">`.

---

## 2. Mathematical Color Contrast Analysis (WCAG 2.2 AA Standard)

Extracted Hex codes were run through a relative luminance algorithm to calculate contrast ratios against the WCAG 2.2 AA standard (minimum 4.5:1 for normal text, 3:1 for large text/UI components).

### 2.1 Pass / Fail Matrix

| Component | Background Hex | Foreground Hex | Ratio | WCAG 2.2 Status |
| :--- | :--- | :--- | :--- | :--- |
| Primary Button (Web) | `#1D4ED8` | `#FFFFFF` | 6.70:1 | **PASS** |
| Generate Button (Web) | `#10B981` | `#FFFFFF` | 2.54:1 | **FAIL** (Severe) |
| Input Placeholder (Web) | `#E5E7EB` | `#9CA3AF` | 2.05:1 | **FAIL** (Severe) |
| Study Plan Container | `#FFFFFF` | `#4B5563` | 7.56:1 | **PASS** |
| Scripture Reader Body (Mobile) | `#F9FAFB` | `#111827` | 16.98:1| **PASS** |
| Scripture Reader Secondary | `#F9FAFB` | `#6B7280` | 4.63:1 | **PASS** |
| Commentary Button (Mobile)| `#2563EB` | `#FFFFFF` | 5.17:1 | **PASS** |

### 2.2 Contrast Remediation Imperatives
1.  **Generate Button:** The green (`#10B981`) on white fails contrast requirements. It must be darkened to at least `#059669` (Ratio 3.2:1) for large text, or `#047857` (Ratio 4.48:1) for standard text.
2.  **Input Placeholders:** Light gray (`#9CA3AF`) on off-white (`#E5E7EB`) is entirely illegible for low-vision users. The placeholder text must be darkened (e.g., `#6B7280`), and reliance on placeholders for instructions should be replaced with permanent external labels.
