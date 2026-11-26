# Validation rules

`tae validate` checks one product's threat model against built-in rules and any custom
rules you add. The same checks run inside `tae report build`.

```sh
tae validate payments.snapshot.json                      # table in the terminal
tae validate --product "Payments API"                    # pull live instead of from a file
tae validate snap.json -r validation.yaml                # custom rules and overrides
tae validate snap.json --format junit -f report.xml      # GitLab test report
tae validate snap.json --format codequality -f gl-code-quality-report.json
tae rules                                                # list all rules and their levels
```

| Exit code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-level` (default `error`) |
| 10 | Findings at or above `--fail-level` |
| 3 | Invalid snapshot or validation config |

`--fail-level never` always exits 0, which is useful for reporting without gating.
`--as-of YYYY-MM-DD` fixes the date used for review-date checks, so runs are reproducible.

## Built-in rules

The three priority checks are on by default as **errors**:

- every threat is scored (`CMP001`)
- accepted risks are fully documented, approved and not overdue (`GOV001`, `GOV002`, `GOV003`)
- no high or critical threat is left open (`GOV005`)

| Rule | Level | Title | What it checks |
|---|---|---|---|
| `STR001` | error | Unknown status or type value | Status and type fields must use ThreatAtlas's vocabularies. |
| `STR002` | error | Score out of range | Likelihood and impact scores must be between 1 and 5. |
| `REF001` | error | Threat or mitigation on a missing element | Every threat and mitigation must be attached to a node or edge that exists in the diagram. |
| `REF002` | error | Threat model mismatch | A threat or mitigation must belong to a threat model of the same diagram. |
| `REF003` | warning | Mitigation linked to a missing threat | A mitigation linked to a threat must point at a threat identified on the same diagram. |
| `REF004` | warning | Element type mismatch | `element_type` must match whether the element is a node or an edge. |
| `CON001` | error | Risk score does not match likelihood × impact | Stored inherent and residual scores and severities must match ThreatAtlas's formula and bands. |
| `CON002` | warning | Mitigated threat without an active mitigation | A threat marked mitigated should have at least one implemented or verified mitigation. |
| `CON003` | warning | Residual risk higher than inherent risk | Residual risk after mitigation should not exceed the inherent risk. |
| `CON004` | warning | Completed threat model with open threats | A threat model marked completed should have no threats still in status `identified`. |
| `CMP001` | error | Threat not scored | Every threat needs a likelihood and an impact so its risk can be rated. |
| `CMP002` | warning | Diagram without a threat model | Each diagram should have at least one threat model. |
| `CMP003` | warning | Threat model without threats | A threat model should identify at least one threat. |
| `CMP004` | info | Element without threats | Processes, data stores, external entities and data flows are expected to have threats considered. |
| `CMP005` | warning | Product information incomplete | Required product fields must be filled in (configurable). |
| `CMP006` | error | Diagram has no content | Each diagram must contain at least one element to be reported. |
| `GOV001` | error | Accepted risk not fully documented | An accepted threat needs a justification, an approver and a review date. |
| `GOV002` | error | Accepted risk not approved | An accepted threat must be approved by its approver. |
| `GOV003` | error | Risk review overdue | The review date of an accepted risk has passed. |
| `GOV004` | warning | Risk review due soon | The review date of an accepted risk is coming up (configurable). |
| `GOV005` | error | Open high or critical threat | High and critical threats must be mitigated or formally accepted (severities configurable). |

Risk scores follow ThreatAtlas: `score = likelihood × impact`, and severity is critical at
20 or more, high at 12 or more, medium at 6 or more, otherwise low.

## Validation config file

A YAML file passed with `--rules`, or referenced from a report definition's
`validation.rules`. Every key is optional.

```yaml
disable: [CMP004]            # skip rules
levels:                      # change a rule's level: error | warning | info
  CON002: error
  GOV004: info
params:
  review_warning_days: 30                       # GOV004 window
  open_risk_severities: [high, critical]        # GOV005
  required_product_fields: [description, owner_name, owner_email, reviewer]   # CMP005
  uncovered_element_types: [process, datastore, external, flow]               # CMP004
rules: []                    # custom rules, see below
risk_scales: [../models/payments-framework.yaml]   # your own severity bands, see import.md
```

With a custom risk scale (`risk_scales`, or `tae validate --risk-scale FILE`), threats of
that scale's frameworks get their severity from your bands, which affects rules such as
`GOV005`. `CON001` still checks ThreatAtlas's stored values against ThreatAtlas's bands.

Unknown rule IDs, unknown keys and malformed rules are rejected with exit code 3, so a
typo can't silently switch a check off.

## Custom rules

```yaml
rules:
  - id: CUSTOM-001                       # A–Z, 0–9, - and _; must not clash with built-in IDs
    title: High risks need a decision
    level: error                         # error | warning | info (default warning)
    applies_to: diagram_threat
    when:    { severity: [high, critical] }        # which entities the rule applies to
    require: { status: [mitigated, accepted] }     # what must hold for each of them
    message: "{ref} {name} on {element_label} is {severity} and still {status}"
```

`when` is optional (the rule then applies to every entity of that type). A finding is
raised for each entity that matches `when` but not `require`.

### Conditions

| Form | Meaning |
|---|---|
| `field: value` | equal (strings compare case-insensitively) |
| `field: [a, b]` | one of |
| `field: {op: value, ...}` | every operator must hold |

Operators: `eq`, `ne`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `exists` (true/false),
`empty` (true/false), `matches` (regular expression), `contains` (substring, case-insensitive).

Date fields accept ISO dates (`2027-01-31`), `today`, `today+30` or `today-7`:

```yaml
require: { acceptance_review_date: { lte: "today+365" } }
```

Messages can use any field of the entity as `{field}`. Rules are data, never code: no
expressions are evaluated.

### Fields

| `applies_to` | Fields |
|---|---|
| `diagram_threat` | `id`, `ref`, `name`, `description`, `category`, `status`, `likelihood`, `impact`, `risk_score`, `severity`, `residual_likelihood`, `residual_impact`, `residual_score`, `residual_severity`, `residual_comments`, `comments`, `acceptance_justification`, `acceptance_approver_id`, `acceptance_approver_name`, `acceptance_review_date`, `acceptance_review_status`, `acceptance_review_note`, `accepted_at`, `element_id`, `element_label`, `element_type`, `element_kind`, `diagram`, `diagram_id`, `framework`, `model`, `model_status`, `mitigation_count`, `active_mitigation_count`, `is_custom_threat` |
| `diagram_mitigation` | `id`, `ref`, `name`, `description`, `category`, `status`, `comments`, `element_id`, `element_label`, `element_type`, `element_kind`, `diagram`, `diagram_id`, `linked`, `threat_ref`, `threat_name`, `threat_severity`, `threat_status` |
| `diagram` | `id`, `name`, `description`, `node_count`, `edge_count`, `model_count`, `threat_count`, `open_threat_count`, `mitigation_count` |
| `model` | `id`, `name`, `description`, `status`, `framework`, `diagram`, `diagram_id`, `threat_count`, `open_threat_count`, `completed_at` |
| `element` | `id`, `label`, `has_label`, `type`, `kind`, `diagram`, `diagram_id`, `threat_count`, `mitigation_count` |
| `product` | `id`, `name`, `description`, `status`, `is_public`, `repository_url`, `confluence_url`, `application_url`, `business_area`, `owner_name`, `owner_email`, `jira_project_key`, `reviewer`, `contributors`, `diagram_count`, `threat_count`, `open_threat_count`, `mitigation_count` |

`element_type` is `process`, `datastore`, `external`, `boundary` or `flow` (for edges);
`element_kind` is `node` or `edge`. An element without a label shows its ID as `label`; use
`has_label` to check whether it really has one. See [examples/rules/custom-rules.yaml](../examples/rules/custom-rules.yaml).

## In GitLab CI

```yaml
threat-model:
  image: $CI_REGISTRY/your-group/threatatlas-exporter:latest
  script:
    - tae pull --product "$PRODUCT" -f snapshot.json
    - tae validate snapshot.json --format junit -f report.xml
  artifacts:
    when: always
    reports: { junit: report.xml }
```

A complete template is in [examples/gitlab/threat-model.gitlab-ci.yml](../examples/gitlab/threat-model.gitlab-ci.yml).
