# EASE-Bot demo video script (target 2:30, hard max 3:00)

Record the screen at 1080p. Show only public pages: the ease-bot repo, the demo PR, and the Actions run.
Never show the repository Settings → Secrets page or any terminal that prints environment variables.

| Time | On screen | Voiceover |
|---|---|---|
| 0:00–0:15 | Title card: "EASE-Bot: verified IaC fixes on your pull request" | "AI can fix Terraform and Kubernetes security issues. But in my research, more than half of the scanner-passing fixes from one popular open model still broke deployment or changed what the file does. EASE-Bot only shows you fixes that survive a verifier." |
| 0:15–0:35 | Demo PR #1 → *Files changed*: public S3 ACL, unencrypted EBS, SSH open to 0.0.0.0/0, privileged container on the host network | "Here's a pull request with some classic mistakes: a public bucket, an unencrypted volume, SSH open to the internet, and a privileged container sharing the host network." |
| 0:35–0:55 | *Checks* tab → EASE-Bot run log: scanning both files, then `verified` for each | "When the PR opens, the EASE-Bot Action scans the changed files with Checkov and Trivy, then asks a free Groq model for a fix." |
| 0:55–1:30 | Summary comment: verdict table (35 → 0, 14 → 0), expand a file: Verification, Repair rounds, Needs a human decision | "Every candidate has to pass four gates: terraform validate or kubeconform strict, an intent check so no resource, image, port or rule block disappears, a re-scan with no new findings, and at least one finding removed. If it fails, the reason goes back to the model for another round. Findings that need a human, like a KMS key or a log bucket, are listed but never auto-fixed." |
| 1:30–1:55 | *Files changed*: inline suggestion on deployment.yaml → hover *Add suggestion to batch* (don't commit) | "What survives is posted as GitHub suggested changes, so a reviewer can apply it in one click." |
| 1:55–2:20 | README section "Things the verifier has caught": deleted SSH rule, invented EC2 instance, pod-level securityContext | "In testing, the model deleted an SSH rule instead of restricting it, invented an EC2 instance, and put container-only fields at pod level. The scanners accepted that last one. The verifier caught all three." |
| 2:20–2:40 | README quick start (workflow YAML) + test badge / Actions tests passing | "Setup is one workflow file and a free Groq key. It's open source, MIT licensed, with 54 tests. Scanner-green isn't the same as safe, so EASE-Bot checks the rest." |

Tips
- If the PR has been re-run and shows different numbers, read the numbers off the screen instead of the script (LLM output varies between runs).
- Keep it under 3:00: the rules say 2–3 minutes max.
- Upload to YouTube as Public (or Unlisted if the rules allow it) and paste the link into `submission.md`.
