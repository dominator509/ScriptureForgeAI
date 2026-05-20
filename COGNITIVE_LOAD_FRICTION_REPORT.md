# Phase 3: Cognitive Load & Workflow Friction Analysis

This phase evaluates the system heuristics and cognitive friction across the three designated "Golden Path" workflows. Friction is quantified by calculating the required click-depth, the visibility of system state, and the potential for error-recovery fatigue.

---

## Workflow 1: Searching for a Scripture

### 1. Context & Persona
*   **Persona:** Everyday Believer (`User`), Pastor/Teacher (`Author`)
*   **Interface:** Web Application / Mobile Application
*   **Goal:** Locate a specific verse or theological concept rapidly during a live study or sermon prep.

### 2. Friction Mapping (Current State)
1.  **Action:** User clicks "Search" icon (Top Nav). -> *Cognitive Load: Low*
2.  **Action:** User types query (e.g., "grace in ephesians" or "John 3:16").
3.  **System State:** Asynchronous debounced fetch to Rust gRPC engine via Go backend.
4.  **Feedback:** UI displays a spinner. If vector search takes >1s, user waits.
5.  **Action:** User selects the desired result from a dropdown or list. -> *Cognitive Load: Medium (Scanning required)*

### 3. Heuristic Evaluation & Friction Quantification
*   **Visibility of System Status (Nielsen #1):** **PASS**. The UI provides a loading spinner during the network request.
*   **Flexibility and Efficiency of Use (Nielsen #7):** **FAIL (Moderate Friction)**.
    *   *Observation:* If a user searches for a specific coordinate (e.g., "Rom 8:1"), standard full-text search patterns force them to scan a list of results and click the top match.
    *   *Friction Cost:* +1 unnecessary click. +2 seconds of scanning time.
    *   *Recommendation:* Implement an "Exact Match Auto-Route" or Command Palette (Cmd+K). If the regex pattern explicitly matches a book/chapter/verse, hitting 'Enter' should immediately render the reader view, bypassing the search results list entirely.

---

## Workflow 2: Creating an AI Study Plan

### 1. Context & Persona
*   **Persona:** Small Group Leader (`Moderator`), Pastor (`Author`)
*   **Interface:** Web Application (Workspace)
*   **Goal:** Generate a multi-week curriculum based on a theological topic or book of the Bible.

### 2. Friction Mapping (Current State)
1.  **Action:** User navigates to Dashboard -> "AI Tools" -> "Study Plan Generator". (Click Depth: 3)
2.  **Action:** User fills out a form: Topic (Text), Duration (Dropdown), Denominational Guardrails (Multi-select), Target Audience (Dropdown). -> *Cognitive Load: High (Decision fatigue)*
3.  **Action:** User clicks "Generate Plan" (Identified in Phase 2 as having poor color contrast).
4.  **System State:** Heavy MapReduce job initiated. Go backend coordinates with LLM.
5.  **Feedback:** UI shows "Generating...".
6.  **Action:** Wait (Potentially 10-30 seconds depending on plan complexity).
7.  **System State:** Plan rendered.
8.  **Error Path:** If verification fails (citation validation regex fails), UI returns "Failed to generate plan." -> *Cognitive Load: Extreme (Total loss of progress)*

### 3. Heuristic Evaluation & Friction Quantification
*   **Error Prevention (Nielsen #5):** **FAIL (High Friction)**.
    *   *Observation:* The user invests significant cognitive effort defining parameters, only to lose all context if the background AI verification subsystem rejects the output due to a hallucinated citation.
    *   *Friction Cost:* Total workflow restart. Devastating DX/UX.
    *   *Recommendation:* Implement localized, progressive generation. Generate the outline first (fast), allow the user to approve it, and then generate the deep content (slower). If verification fails on a specific paragraph, retry that chunk automatically in the background rather than failing the entire request.
*   **User Control and Freedom (Nielsen #3):** **FAIL**. There is no visible way to "Cancel" the generation once it starts if the user realizes they made a typo in the topic.

---

## Workflow 3: Multiple-User Zoom Bible Study Call

### 1. Context & Persona
*   **Persona:** Small Group Leader (`Moderator` - Host), Everyday Believer (`User` - Participant)
*   **Interface:** Web Application (Live Room Canvas)
*   **Goal:** Launch a synchronized study room natively integrated with Zoom video and synchronized scripture focus.

### 2. Friction Mapping (Current State)
1.  **Action (Host):** Navigates to Group -> "Start Live Room". (Click Depth: 2)
2.  **System State:** Go backend `CreateMeeting` via Zoom Adapter. Webhook established.
3.  **Action (Host):** Click "Join Video". Zoom client launches or embedded WebSDK initializes.
4.  **Action (Participant):** Receives Push Notification / sees active room on dashboard. Clicks "Join". (Click Depth: 1)
5.  **System State:** WebSocket connection established. Participant state synced.
6.  **Action (Host):** Navigates to a scripture passage.
7.  **System State:** WebSocket fires `RealtimeStateEvent`. All participant screens scroll to match the Host.

### 3. Heuristic Evaluation & Friction Quantification
*   **Match between System and Real World (Nielsen #2):** **PASS**. The concept of "Host changes page, everyone else sees it" perfectly mimics a physical Bible study.
*   **Help and Documentation (Nielsen #10):** **FAIL (Moderate Friction)**.
    *   *Observation:* Permissions regarding *who* controls the screen are implicit. If a participant tries to scroll away to read ahead, does it break the sync? Does the UI snap them back?
    *   *Friction Cost:* Confusion regarding local control vs. remote control.
    *   *Recommendation:* Introduce a clear "Sync Status" indicator. If a user scrolls manually, display a non-intrusive floating button: "Resume Sync with Host".
*   **Visibility of System Status (Nielsen #1):** **FAIL (Edge Case)**. If the WebSocket connection drops silently, the UI might still look active, but sync events are missed.
    *   *Recommendation:* Implement a strict heartbeat mechanism on the client. If missed, immediately display a discreet "Reconnecting..." state bar to prevent the user from assuming the Host has simply stopped teaching.
