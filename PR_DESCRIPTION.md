# 🧪 [testing improvement description]
Add unit tests for the pure function BuildRigorousPrompt

## 🎯 What
The untested pure function `BuildRigorousPrompt` in `internal/adapters/llm/client.go` lacked testing to verify structural bounds around interactions with external Large Language Models.

## 📊 Coverage
The new test (`internal/adapters/llm/client_test.go`) verifies that:
1. Exactly two `openaiMessage` structs are generated.
2. The initial struct is mapped to the `system` role.
3. The system prompt contains the explicit execution bounds.
4. The system prompt correctly appends the `compiledContext` containing bounded citations.
5. The subsequent message struct maps to the `user` role and reliably reflects the `safePrompt` string input.

## ✨ Result
Test coverage over the specific boundaries enforced for the RAG prompt has been fortified, catching structural faults should regressions be accidentally pushed. Test suite passes successfully.
