# Devpost submission draft: Arbiter Hacks V1

- **Hackathon:** Arbiter Hacks V1 (https://arbiter-hacks-v1.devpost.com/)
- **Track:** General Track (pick this when registering; one track only)
- **Deadline:** 20 Dec 2026 9:00pm PST = Mon 21 Dec 2026 3:30pm Adelaide time
- **Team:** solo (Shohrab Hossen Niaz)

## Project name
EASE-Bot

## Tagline (elevator pitch)
An LLM fixes your Terraform and Kubernetes security issues on the pull request, and a verifier throws away every fix that doesn't validate, changes what the file does, or adds a new finding.

## Links
- Code (public, MIT): https://github.com/shohrabniaz/ease-bot
- Live demo PR (the bot's real suggestions and summary): https://github.com/shohrabniaz/ease-bot-demo/pull/1
- Demo repository: https://github.com/shohrabniaz/ease-bot-demo
- Video (2–3 min, YouTube): TODO

## Inspiration
I work as a DevSecOps engineer and my research is on LLM repair of Infrastructure-as-Code security problems. In my study of 499 Kubernetes and Terraform files, 52.9% of the fixes from `openai/gpt-oss-120b` that made the scanner pass still failed to deploy or changed what the file does (11.7% for Gemini). Most "AI fixes your IaC" tools stop at "the scanner is green". I wanted a bot that brings the missing checks into the place where engineers actually review infrastructure: the pull request.

## What it does
EASE-Bot is a GitHub Action. On every pull request that touches `.tf` or Kubernetes YAML it:
1. Scans only the changed files with Checkov and Trivy, and marks which findings the PR introduced.
2. Asks an LLM (Groq's free tier, `openai/gpt-oss-120b`) for a complete fixed file.
3. Runs every candidate through a verifier. The fix must pass `terraform validate` or `kubeconform -strict`; it must keep every resource, Kubernetes object, container, image, port and nested Terraform block; the re-scan must show no new findings; and at least one finding must go away.
4. If a candidate fails, the reason goes back to the model and it gets another try (up to 3 rounds).
5. Posts the surviving fix as GitHub suggested changes you can commit in one click, plus a single summary comment with a verdict per file: ✅ verified, 🟡 partial, or ❌ rejected.

Findings that need a human decision (a KMS key, a log bucket, an image digest, a replication region) are reported but never handed to the model, because in testing it "solved" them by inventing resources, like an EC2 instance with a made-up AMI.

On the demo PR it fixed all 49 fixable findings across a Terraform file and a Kubernetes Deployment, every fix passed `terraform validate` / `kubeconform -strict`, and 13 findings were listed for a human decision.

## How I built it
- Python package (`easebot`) with a CLI for local runs and a composite GitHub Action (`action.yml`).
- Scanners: Checkov and Trivy behind one `Finding` type, so findings can be compared before and after a fix by scanner, rule and resource.
- LLM: any OpenAI-compatible endpoint; Groq's free tier by default, plus an offline `mock` mode so the whole pipeline and tests run without a key.
- Verifier: `terraform validate` run with the other `.tf` files in the same folder, `kubeconform -strict` for Kubernetes schemas, and a structural intent check (resource addresses, objects, containers, images, ports, and nested Terraform blocks via the HCL parser that ships with Checkov).
- GitHub integration: `difflib` turns the fixed file into suggestion hunks, which are posted only when they fit inside the PR diff. One sticky summary comment is updated on each push, and stale suggestions are replaced, not duplicated.
- Safety: the key is only read from the environment and never logged; action inputs reach the script through env vars, not string interpolation; Trivy and kubeconform downloads are pinned and SHA-256 checked; the workflow token needs only `pull-requests: write`.
- 54 pytest tests, including a property test that applying every posted suggestion reproduces the verified file exactly, and a test that the API key never appears in reports or error messages. They run in GitHub Actions on every push.

## Challenges I ran into
- Groq's JSON mode failed on whole files full of quotes and braces, so I switched to a plain "NOTES / FIXED_FILE" format with a tolerant parser.
- The model kept finding ways to pass the scanner without making things safer. It deleted the SSH ingress rule instead of restricting it, invented an EC2 instance to satisfy "security group must be attached", and put container-only fields into the pod security context. Checkov and Trivy accepted that last one; `kubeconform -strict` did not. Each of these became a verifier rule or a deferred check.
- In one run the model said it had fixed the open-SSH finding, but the re-scan still reported it. The bot now marks model claims that the re-scan contradicts and gives a 🟡 partial verdict.
- GitHub only accepts suggestions on lines inside the PR diff, so a full-file fix has to be split into hunks that map onto the diff. Each hunk has to be anchored correctly for insertions and deletions.

## Accomplishments that I'm proud of
- It works live: on the demo PR the Action fixed all 49 fixable findings, and every fix passed validation and the intent check before it was shown.
- The verifier caught real model mistakes that two mainstream scanners missed.
- It costs nothing to run: a free Groq key and GitHub Actions.

## What I learned
- "The scanner passes" is a weak signal for LLM fixes. Validity and intent checks catch a different class of errors, and they belong in CI, not only in research.
- Feeding the verifier's reason back to the model works better than one-shot prompting. Rules like "never delete a block to silence a finding" have to be enforced in code, not just written in the prompt.
- Some security checks need a human decision. Being clear about which ones made the bot more trustworthy, not less.

## What's next
- Add `terraform plan` against a mocked provider and a Kubernetes server-side dry run in a throwaway kind cluster.
- Expand the intent check to selectors, labels, replicas and commands.
- Publish to the GitHub Marketplace, and add per-repo policy files for deferred checks.
- Measure acceptance rates of suggestions on real repositories, as a follow-up to my study.

## Built with (tags)
python, github-actions, checkov, trivy, terraform, kubernetes, kubeconform, groq, gpt-oss-120b, llm, devsecops, pytest

## Work done during the event vs before
- All EASE-Bot code, the Action, the tests and the demo repository were written during the submission period (it opened 20 Oct 2026). The first commit was on 9 Nov 2026.
- Before the event: the research idea and published numbers come from my own IaC-repair study, and I earlier built a separate web app, MisconfigExplained, that explains single files. EASE-Bot reuses no code from either; it is a new CI/PR tool.
- Tools: I used an AI coding assistant while building this. TODO: decide whether to state this on Devpost (the rules page does not ask).

## Screenshots to upload (TODO)
1. The summary comment on the demo PR (verdict table).
2. An inline "suggested change" on `infra/k8s/deployment.yaml`.
3. The Actions run log showing `verified` for both files.
4. The mermaid architecture diagram from the README.
