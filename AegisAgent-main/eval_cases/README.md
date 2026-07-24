# Evaluation Cases

This directory intentionally contains only lightweight public examples in the
repository.

Local benchmark, CVE reproduction, and mainstream-agent evaluation manifests may
reference large samples under `real_samples/`; those archives are not committed.
Keep those local manifests out of the public repository unless their sample
inputs are also public and small enough for normal Git hosting.

Run the bundled example cases:

```powershell
python -m agent_sandbox.evaluation --cases eval_cases/examples.json --samples-root examples/eval_samples --modes baseline_static
```
