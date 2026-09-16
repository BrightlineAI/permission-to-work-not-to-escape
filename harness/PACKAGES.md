# Python package control

This guide retains the version 2 universal-wheel workflow. For version 3 native Python libraries, extras, source builds, npm and TypeScript, use the [current package guide](ECOSYSTEMS.md). Existing version 2 policies retain their narrower meaning.

This is the first usable prototype of the package control, separate from the paper's experiments. It installs reviewed Python wheel sets for confined project workloads. It is not a replacement for pip everywhere on your machine.

One approved project policy controls:

| Setting | Effect |
|---|---|
| allowed_names | Only these PyPI packages, including dependencies |
| deny_cvss_at_or_above: 9.0 | Reject known critical vulnerabilities with CVSS base score 9.0 or higher |
| min_release_age_days: 3 | Reject an artifact uploaded less than three days ago; zero disables this rule |
| evidence_max_age_seconds: 900 | Recheck freshness before publishing the installed set |
| Existing escalation thresholds | File and package violations share the same project and ancestor task counters |

Each task lists a subset of the project package names. A delegate may only narrow its parent's subset. There are no separate pip or uv policy settings to keep synchronized.

Missing severity, stale data, network failure or unsupported packages block installation without counting as misconduct. A confirmed forbidden package or policy violation counts even if another advisory has incomplete severity.

## Install

Use an ordinary x86_64 Linux account with a working systemd user manager. An administrator may need to install git, curl, python3 and bubblewrap. The control needs no LLM, API key, Node or Codex.

    git clone https://github.com/BrightlineAI/permission-to-work-not-to-escape.git
    cd permission-to-work-not-to-escape
    PTW_INSTALL="$PWD/../ptw-package-install"
    bash harness/scripts/install-vps.sh --no-codex "$PTW_INSTALL"
    export PATH="$PTW_INSTALL/venv/bin:$PTW_INSTALL/bin:$PATH"
    ptw doctor

Use a new installation directory. Doctor must report ready=true. The installer pins uv, nono and Python dependencies in a private environment; it does not change system packages. Omit --no-codex if you also want the existing model adapter.

## New project: allow a safe install, deny a vulnerable one

Create the example and inspect its policy:

    PTW_PROJECT="$PWD/../ptw-package-example"
    ptw sample --packages --out "$PTW_PROJECT"
    ptw review --policy "$PTW_PROJECT/policy.json" --inventory "$PTW_PROJECT/inventory.json"

The frontend task may request idna and django. Operations may install neither. Both share warning at one violation and stopping at three. The sample permits checking Django, not installing a version that violates the vulnerability rule.

Review the settings, then approve the displayed hash:

    ptw approve --policy "$PTW_PROJECT/policy.json" --inventory "$PTW_PROJECT/inventory.json" \
      --sha256 PASTE_THE_REVIEW_HASH --reviewer "Your name" --out "$PTW_PROJECT/approved.json"
    ptw activate --state "$PTW_PROJECT/controller" --bundle "$PTW_PROJECT/approved.json"
    ptw register --state "$PTW_PROJECT/controller" --project website --task frontend \
      --out "$PTW_PROJECT/parent.json"
    ptw package-install --state "$PTW_PROJECT/controller" --session "$PTW_PROJECT/parent.json" \
      --event good-install-1 --requirements "$PTW_PROJECT/requirements.txt" --out "$PTW_PROJECT/receipt.json"

The supplied file pins idna==3.11. Expect allowed=true and a package_set ID. If live advisory data has changed or a service is unavailable, inspect the reason; do not bypass the check.

Use that ID to run the installed library inside the sandbox:

    ptw launch --state "$PTW_PROJECT/controller" --session "$PTW_PROJECT/parent.json" \
      --package-set PASTE_THE_PACKAGE_SET_ID -- /usr/bin/python3 -c \
      "import idna; open('/resources/ui','w').write(idna.encode('bücher.de').decode())"

Within a few seconds, resources/ui.txt should contain xn--bcher-kva.de. The package set is mounted read only at /packages. Workloads cannot see the controller, install into the published set, or access the network. The launch command returns a unit ID before the workload completes; inspect the actual output file, not only that ID.

Now request the intentionally vulnerable example:

    ptw package-install --state "$PTW_PROJECT/controller" --session "$PTW_PROJECT/parent.json" \
      --event bad-install-1 --requirements "$PTW_PROJECT/unsafe-requirements.txt"
    ptw status --state "$PTW_PROJECT/controller" --project website
    ptw events --state "$PTW_PROJECT/controller" --project website

Django==3.2.0 should be denied before download, with critical advisory IDs and a warning. Denied or operationally blocked installs exit 1; malformed input exits 2. Three confirmed violations across registered agents stop the project and its registered processes. Use a new event ID for a new attempt; retries reuse the same ID and exact pins and do not count twice.

## Your package set

The requirements file is deliberately small: one exact name==version per line, including every active dependency. Blank lines and whole-line comments are allowed. Approve every dependency name in both project and task scope.

The broker checks each pinned version, verifies downloaded SHA256 values, inspects wheel metadata and validates dependency closure. uv installs those exact local wheels offline, without dependency resolution or source builds, inside bubblewrap. Publication rechecks session scope, evidence freshness and project stop state. Package code runs only later in a confined workload, not during installation in the controller.

Version 2 accepts universal py3-none-any wheels, including py2.py3 tags. It rejects source distributions, native platform wheels, extras, URL dependencies, editable installs, startup hooks and wheel relocation data. Dependency markers are evaluated for /usr/bin/python3 on the execution host, not the installer's private Python. Incomplete dependency pins block rather than fetching anything else.

For another adapter, call PackageControl(store).install(token, event_id, exact_pins)
from the trusted controller. Keep credentials outside model access. This is a broker
operation, not an unrestricted shell command. The legacy file-only model loop does
not generate package requests; version 4 repository workflows and
[protected interactive Codex](INTERACTIVE.md) do.

## Existing project

Keep your files and file grants. Set PTW_EXISTING to an existing project with a reviewed version 1 policy, not the version 2 example above:

    PTW_EXISTING="/absolute/path/to/your/existing-project"
    ptw package-draft --policy "$PTW_EXISTING/policy.json" \
      --project-id website-packages --task frontend --allow idna \
      --min-age-days 3 --deny-cvss 9 --out "$PTW_EXISTING/package-draft.json"
    ptw review --policy "$PTW_EXISTING/package-draft.json" --inventory "$PTW_EXISTING/inventory.json"

This creates an unapproved version 2 draft, gives package scope only to the named task, and preserves file grants and escalation. Repeat --allow for each dependency. It is an explicit operator configuration, not a claim that an LLM inferred safe dependencies.

For the website/frontend example, approve and switch explicitly:

    ptw approve --policy "$PTW_EXISTING/package-draft.json" --inventory "$PTW_EXISTING/inventory.json" \
      --sha256 PASTE_THE_NEW_REVIEW_HASH --reviewer "Your name" --out "$PTW_EXISTING/package-approved.json"
    ptw stop --state "$PTW_EXISTING/controller" --project website
    ptw activate --state "$PTW_EXISTING/controller" --bundle "$PTW_EXISTING/package-approved.json"
    ptw register --state "$PTW_EXISTING/controller" --project website-packages --task frontend \
      --out "$PTW_EXISTING/package-session.json"

Use your real project and task IDs. Confirm the old project's registered workloads stopped before activating the new identity. Old records remain; the new identity has its own counters. This is an operator-reviewed transition, never an agent shortcut around stopping. Use package-install and launch with the new session. Existing application environments are not modified or retroactively certified.

Version 2 policies can be edited as new drafts and reviewed normally. Never edit active database state. Version 1 policies continue to work, with no package installation authority.

## Verify it yourself

After installation, from the repository root:

    python harness/scripts/validate.py --linux --out ../ptw-package-validation
    python harness/scripts/package_walkthrough.py --out ../ptw-package-walkthrough

Use fresh output directories. The first command includes synthetic positive, negative, race, dependency and Linux effect tests. The second follows the public CLI on real PyPI/OSV data for a new project and an existing project. It tests an actual import, vulnerability rejection, shared escalation and a deliberately strict age policy. It automatically approves only its known synthetic fixture policies, not yours.

Both commands exit nonzero if an assertion fails. The walkthrough needs internet access in the trusted operator process, not in workloads. No model calls or credentials are needed.

## Limits

This gate checks known advisory data, not whether all package code is safe. Unknown vulnerabilities and malicious code without an advisory remain possible. Age is an artifact upload age, not a guarantee of safety. Installed sets are checked at installation; continuous advisory rescanning is future work.

This is not a machine-wide package firewall or arbitrary shell interceptor. An unconfined agent can bypass it; arbitrary code in sandbox scratch space is not automatically classified as a package. System runtime libraries are trusted and are not audited by this gate. Use only the bounded adapter and registered confined workloads for the stated guarantees.

The host, operator account, clock, public metadata services and pinned installation tools are trusted. Current scope is one Linux host, PyPI, at most 64 pins, 20 MiB per download, 100 MiB per set and 200 MiB expanded. No remote uninstall, rollback of completed effects or automatic policy widening is claimed.

See the [design review](PACKAGES_PLAN.md) and [validation record](validation/packages-20260916/README.md).
