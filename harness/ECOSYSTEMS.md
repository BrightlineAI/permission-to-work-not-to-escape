# Python, JavaScript and TypeScript package controls

This prototype checks package scope, known vulnerabilities and release age before publishing an environment for confined workloads. Python and npm share one approved policy, task subsets and escalation history. No model call is needed.

## What works

| Input | Installation and execution |
|---|---|
| Exact Python pins | Pure and compatible native wheels, dependency markers, extras and wheel data |
| PyPI source distributions | Explicitly authorized offline PEP 517 builds, with all build dependencies supplied and checked |
| npm lock version 2 or 3 | Public registry packages, scoped names, nested versions, peers and optional dependencies |
| JavaScript / TypeScript | CommonJS, ESM, TypeScript compilation and package executables |
| npm install scripts | Only for named packages in the approved build list; confined and offline |

This does not mean every library works. A source package needing unavailable system headers or a build that downloads additional binaries will be blocked. The gate checks packages, not whether their code is universally safe.

## Install

Use an ordinary x86_64 Linux account, with Python 3, git, curl, bubblewrap and a working systemd user manager. For npm packages, also install Node 22 and npm 10 using your administrator's supported distribution. The installer does not replace system packages.

    git clone https://github.com/BrightlineAI/permission-to-work-not-to-escape.git
    cd permission-to-work-not-to-escape
    PTW_INSTALL="$PWD/../ptw-install"
    bash harness/scripts/install-vps.sh --no-codex "$PTW_INSTALL"
    export PATH="$PTW_INSTALL/venv/bin:$PTW_INSTALL/bin:$PATH"
    ptw doctor
    node --version
    npm --version

Use a fresh installation directory. Doctor must report ready=true. No OpenRouter, Codex or other API key is required. Python-only use does not require Node/npm; omit those version checks.

## New project: native Python

From the repository root:

    PTW_PROJECT="$PWD/../native-example"
    ptw sample --out "$PTW_PROJECT"
    cp harness/examples/packages/python-native.txt "$PTW_PROJECT/requirements.txt"
    ptw package-draft --policy "$PTW_PROJECT/policy.json" \
      --project-id native-example --task frontend --native \
      --requirements "$PTW_PROJECT/requirements.txt" --out "$PTW_PROJECT/packages.json"
    ptw review --policy "$PTW_PROJECT/packages.json" --inventory "$PTW_PROJECT/inventory.json"

Review the actual policy. The draft proposes numpy only for the frontend task, native wheels, a three-day minimum age and rejection of CVSS scores at or above 9. Nothing is activated yet. Approve the hash displayed by review:

    ptw approve --policy "$PTW_PROJECT/packages.json" --inventory "$PTW_PROJECT/inventory.json" \
      --sha256 PASTE_REVIEW_HASH --reviewer "Your name" --out "$PTW_PROJECT/approved.json"
    ptw activate --state "$PTW_PROJECT/controller" --bundle "$PTW_PROJECT/approved.json"
    ptw register --state "$PTW_PROJECT/controller" --project native-example --task frontend \
      --out "$PTW_PROJECT/session.json"
    ptw package-install --state "$PTW_PROJECT/controller" --session "$PTW_PROJECT/session.json" \
      --event native-1 --requirements "$PTW_PROJECT/requirements.txt" --out "$PTW_PROJECT/receipt.json"
    ptw launch --state "$PTW_PROJECT/controller" --session "$PTW_PROJECT/session.json" \
      --package-set PASTE_PACKAGE_SET_ID -- /usr/bin/python3 -c \
      "import numpy; open('/resources/ui','w').write(str(int(numpy.array([1,2,3]).sum())))"

The receipt supplies the package set ID. Check resources/ui.txt: it should contain 6. Launch returns before completion, so verify the file after a few seconds. The environment is mounted read only at /packages. The workload interpreter is /usr/bin/python3, not the installer's private Python.

### Extras and source builds

Use python-extras.txt instead to test requests[socks]. Every dependency is pinned and independently checked; selecting an extra does not authorize new packages.

For python-source.txt, add --build pypi:stopit to package-draft. The supplied setuptools, wheel and packaging pins are checked just like the source package. uv resolves build requirements only from checked local artifacts, with no network. Missing build dependencies fail with a diagnostic; add exact pins to a new reviewed draft, never give the builder network access.

The receipt records both the source artifact hash and the generated wheel hash. Builds run in a registered resource-limited namespace. They cannot see controller state, credentials or project resources, and a project stop terminates them.

For an existing requirements file, supply a complete exact pin set, one name[optional-extra]==version per line. Whole-line comments and blank lines are accepted. Ranges, direct URLs and editable paths are not registry pins. Use your normal trusted locking workflow first; do not run an untrusted build backend outside the harness to create a lock.

## New project: npm and TypeScript

Create a separate sample and prepare an npm lock without installing packages or running their scripts:

    PTW_NODE="$PWD/../node-example"
    ptw sample --out "$PTW_NODE"
    cp harness/examples/packages/package.json "$PTW_NODE/package.json"
    npm install --prefix "$PTW_NODE" --package-lock-only --ignore-scripts --no-audit --no-fund \
      --registry=https://registry.npmjs.org --userconfig=/dev/null \
      --globalconfig="$PTW_NODE/empty-global-npmrc"
    ptw package-draft --policy "$PTW_NODE/policy.json" --project-id node-example \
      --task frontend --npm-lock "$PTW_NODE/package-lock.json" --build npm:esbuild \
      --out "$PTW_NODE/packages.json"
    ptw review --policy "$PTW_NODE/packages.json" --inventory "$PTW_NODE/inventory.json"

The draft proposes all locked names, including esbuild's optional platform packages. Review those names. Only esbuild is proposed for an install script. This is an operator review, not automatic permission inferred from a lockfile.

Approve, activate and register as in the Python example, using node-example and PTW_NODE. Then:

    ptw package-install --state "$PTW_NODE/controller" --session "$PTW_NODE/session.json" \
      --event node-1 --npm-lock "$PTW_NODE/package-lock.json" --out "$PTW_NODE/receipt.json"
    ptw launch --state "$PTW_NODE/controller" --session "$PTW_NODE/session.json" \
      --package-set PASTE_PACKAGE_SET_ID -- /usr/bin/node -e \
      "const ts=require('typescript'); const code=ts.transpileModule('const answer: number=42;',{}).outputText; require('fs').writeFileSync('/resources/ui',code)"

Check resources/ui.txt for JavaScript containing 42, with the type annotation removed. npm ci runs offline from checked tarballs, with install scripts disabled. Only explicitly approved packages are then rebuilt. Actual archive identities and dependencies must match the lock. Symlinks must remain inside the published package set; hard-linked build files become independent copies.

Package executables are on PATH. Node dependency lookup works for code in /work as well as /packages; CommonJS and ESM are tested. Put temporary build outputs in /work or /tmp, not the read-only dependency directory. Application files are still accessed through approved resource grants.

## Existing projects and multiple agents

Use your existing policy and inventory instead of sample. package-draft preserves file grants, escalation thresholds, other tasks' package scopes and existing package security thresholds. It does not alter project files or existing environments. --requirements and --npm-lock propose package names for the selected task; --allow can add individual qualified names.

Review and approve a new project identity, stop the old identity, confirm its registered processes stopped, then activate the new bundle. The previous audit history remains. This is an operator migration, not a way for an agent to reset its counter.

Register independent agents against the same project, and delegates with --parent. Task and delegate scopes may only narrow permission. Python, npm and file violations all count toward the same project stop. Missing evidence or a broken build blocks installation without accusing the agent of misconduct.

Use a stable event ID for a retry of the same request, and a new ID for a genuinely new attempt. Exit 1 means denied or operationally blocked; exit 2 means invalid input. Never bypass an age or vulnerability rejection just to make a demo pass.

## Verify the installation

From the repository root, with the installed environment on PATH:

    python harness/scripts/validate.py --linux --out ../ecosystem-unit-results
    python harness/scripts/ecosystem_walkthrough.py --out ../ecosystem-user-results
    python harness/scripts/package_walkthrough.py --out ../legacy-package-results

Use fresh output directories. These exercise real Linux confinement, live registry/OSV checks, native Python, a source build, extras, TypeScript, esbuild, ESM, and existing-project migration. The older walkthrough also checks a known vulnerable Django version and shared escalation. Fixture policies are automatically approved only inside these synthetic walkthroughs.

Reports are saved even after a failed assertion. Registry evidence can change; a newly unsafe or too-young release should fail. Keep the report and review the reason, rather than weakening the policy.

## Remaining boundaries and how to extend them

| Boundary | Safe next step |
|---|---|
| Private registries, Git sources, local editable packages and npm workspaces are not registry installs | Add a reviewed source identity/digest adapter and an explicit credential broker. Until then, separate application source from its public-registry dependency lock. Do not reinterpret local paths as public packages. |
| A build needs absent headers or offline toolchains | Have an operator provision a reviewed runtime image, or supply checked build wheels. Do not let package code install system packages or access the host. |
| Large packages or builds exceed limits | Review resource budgets and use a dedicated build runner before raising them. Current limits: 64 Python pins, 1024 distinct npm versions, 128 MiB per v3 download, 512 MiB per set/export, 768 MiB build memory, 180-second build timeout. |
| Cargo, Maven, NuGet or other package managers | Add an ecosystem evidence/lock/installer adapter using their existing tooling and the same policy/controller/build supervisor. No adapter or vulnerability coverage is claimed yet. |
| Installed environments later become vulnerable | Add scheduled reassessment and policy-driven quarantine. The current receipt describes evidence checked at installation, not continuous certification. |

This is a broker for registered confined workloads, not a machine-wide pip/npm firewall. Unknown vulnerabilities and malicious code without advisories remain possible. System runtime files, the host, operator and evidence services are trusted. Arbitrary external workers are not stopped by this local controller. The original paper and benchmark results are unchanged.

See the [plan and review](ECOSYSTEM_PLAN.md) and [architecture](DESIGN.md).
