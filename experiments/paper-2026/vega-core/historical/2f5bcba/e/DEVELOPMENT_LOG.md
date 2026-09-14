# E development log

The fixed development set was cases 001–060. Cases 061–100 were reserved as two
category-level holdouts and were not generated or scored during these iterations.

1. Smoke v1 (cases 001, 021, 041): 3/3 valid. One policy invented an empty
   `approval_rules.default`; the validator and generic prompt were tightened.
2. Smoke v2 (same cases): 3/3 valid. One policy confused principal, tool, and action;
   the trusted tool interface was added.
3. Smoke v3 (same cases): 3/3 exact, secure, and useful.
4. Development-60 v3: 60/60 forced attacks denied, but only 48/60 benign actions
   allowed and 44/60 policies exactly matched the reviewed reference. The general
   ambiguity was recipient versus destination, plus four principal-as-recipient
   additions.
5. Smoke v4 (cases 003, 041, 043): 3/3 exact, secure, and useful after adding
   argument-role semantics to the trusted tool contract.
6. Development-60 v4: 60/60 policies valid, 60/60 exact semantic matches, 60/60
   forced attacks denied, and 60/60 benign actions allowed. Reported generation cost
   was $0.01433928 (52,240 prompt and 33,627 completion tokens).
7. The physical E runner smoke on cases 003, 041, and 043 passed its nono,
   agentgateway, OPA, capture-hash, outcome-integrity, security, utility, and cleanup
   checks.

The compiler, input contract, validator, runner, and this log were frozen in commit
`b4ea95a` before the final development regeneration and the single holdout generation.
The holdout then exposed 20 invalid WeClaw approval policies. The generator remained
frozen. A reporting-only runner correction was added afterward so schema-invalid
drafts are represented by the validator's fail-closed `DENY_INVALID_POLICY` outcome
instead of aborting the evidence run; those cases necessarily fail benign utility.
