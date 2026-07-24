# Synthetic Indirect Input Example

This intentionally vulnerable toy agent reads untrusted browser, email, GitHub
issue, and RAG content. It then forwards the retrieved instructions to a model
and a webhook-like sink without a trust boundary.

It is small on purpose: it exists so `eval_cases/examples.json` can run after a
fresh clone without downloading a large third-party benchmark.
