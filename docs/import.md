# Importing frameworks and threat models

`tae import FILE` takes a YAML file and makes ThreatAtlas match it. There are two kinds of
file:

| `kind:` | What it defines | Example |
|---|---|---|
| `framework` | A custom threat-modelling methodology: the framework, its threat and mitigation catalogue, and optionally your own risk scale | [payments-framework.yaml](../examples/models/payments-framework.yaml) |
| `threat-model` | One product's analysis: the product, its data flow diagrams, the threat models applied to them, and the threats and mitigations on each element | [payments-threat-model.yaml](../examples/models/payments-threat-model.yaml) |

```sh
tae import examples/models/payments-framework.yaml --dry-run   # show the plan only
tae import examples/models/payments-framework.yaml             # apply it
tae import examples/models/payments-threat-model.yaml          # then the threat model
tae import my-model.yaml --prune                               # also delete what the file no longer has
tae import --schema threat-model > threat-model.schema.json    # JSON Schema for editor autocompletion
```

## How syncing works

- The whole file is checked before anything is sent. That includes references inside the
  file (flows between existing elements, threats on existing elements, mitigations listed
  in the catalogue) and references to ThreatAtlas (frameworks, catalogue threats and
  mitigations).
- The plan is always printed first. `--dry-run` stops there.
- Things are matched **by name**: frameworks, catalogue entries, products, diagrams and
  threat models. Threats on a diagram are matched by their element and catalogue threat;
  mitigations by element, catalogue mitigation and the threat they address.
- New things are created and changed things are updated. Re-importing an unchanged file
  changes nothing.
- **Nothing is deleted** unless you add `--prune`. Without it, things in ThreatAtlas that
  the file no longer contains are listed as notes. With `--prune`, `tae` asks before
  deleting; in CI, add `--yes`.
- **Optional fields you leave out aren't managed.** If a threat in the file has no
  `status`, a status someone set in ThreatAtlas is kept. Fields you do set are kept in
  line with the file.
- **Renaming** something in the file looks like a new entry plus a removed one. Without
  `--prune` you'll get the new entry and a note about the old one.
- If an import stops partway (for example a network error), fix the problem and run it
  again. It picks up where it left off.

> **Custom frameworks are private in ThreatAtlas.** ThreatAtlas shows a custom framework
> and its catalogue only to the account that created it. Import a framework and the
> threat models that use it with the same account. For a team, use a shared service
> account for imports.

## Framework files

```yaml
kind: framework
framework:
  name: Card Payments Threat Model        # unique; can't be a built-in name like STRIDE
  description: In-house methodology for card payment systems.
categories: [Fraud, Cardholder data]      # optional: entries must use one of these
risk_scale: { ... }                       # optional, see below
threats:
  - name: Card testing attack
    category: Fraud
    description: Attackers validate stolen cards with many small authorisations.
    mitigations: [Velocity limits]        # names from the mitigations below
mitigations:
  - name: Velocity limits
    category: Fraud
    description: "Limit attempts per card, device and IP address."
```

ThreatAtlas has no links between catalogue threats and mitigations, so a threat's
`mitigations` are added to its description in ThreatAtlas ("Suggested mitigations: …"),
where analysts see them when identifying the threat.

## Risk scales

ThreatAtlas scores risk as likelihood × impact (1–5 each) with fixed bands: 20 or more is
critical, 12 or more high, 6 or more medium, anything lower low. A framework file can
define your own scale:

```yaml
risk_scale:
  name: Payments risk scale
  likelihood:
    1: { label: Rare, description: Not expected within 5 years }
    # ... levels 1 to 5, all required
  impact:
    1: { label: Negligible, description: No customer or financial impact }
    # ...
  bands: { critical: 16, high: 10, medium: 5 }   # minimum scores; anything lower is low
```

What happens with it:

- **ThreatAtlas:** the scale is written into the framework's description, so analysts see
  what each level means. ThreatAtlas itself keeps scoring with its own bands.
- **`tae`:** when you point `tae` at the file, the threats of that framework get their
  severity from your bands everywhere in `tae`. That covers validation rules (such as "no
  open high or critical threats"), the executive summary, threat tables, diagram badges and
  the risk matrix (with your level names). A **risk scale** section explains it in the
  report.

  ```yaml
  # report definition, or validation config
  risk_scales: [../models/payments-framework.yaml]
  ```

  ```sh
  tae validate snapshot.json --risk-scale examples/models/payments-framework.yaml
  ```

- A scale can also live in its own file (`kind: risk-scale`, the same fields at the top
  level). It then applies to every framework, unless it lists `frameworks: [...]`. A scale
  in a framework file applies to that framework only. Threats from other frameworks keep
  ThreatAtlas's bands.
- The validation rule `CON001` still checks the scores and severities **ThreatAtlas
  stored** against ThreatAtlas's own bands, since those are what ThreatAtlas computed.

## Threat-model files

```yaml
kind: threat-model
product:
  name: Payments API                 # matched by name; created if missing
  owner_name: Pat Owner              # any product field; only the ones given are managed
diagrams:
  - name: Payment flow
    elements:                        # process | datastore | external | boundary
      - { id: shopper, type: external, label: Shopper }
      - { id: dmz, type: boundary, label: DMZ }
      - { id: checkout, type: process, label: Checkout API, boundary: dmz }
    flows:
      - { id: f-checkout, from: shopper, to: checkout, label: Card details (HTTPS) }
    models:
      - framework: Card Payments Threat Model    # or STRIDE, LINDDUN, ...
        name: Payments review 2026               # defaults to the framework name
        threats:
          - threat: Card testing attack          # catalogue name
            element: f-checkout                  # an element or flow ID
            likelihood: 4
            impact: 3
            status: identified                   # identified | mitigated | accepted
            residual: { likelihood: 2, impact: 3, comments: After velocity limits }
            mitigations:
              - { mitigation: Velocity limits, status: implemented }   # proposed | implemented | verified
          - threat: Acquirer outage
            element: f-acquire
            status: accepted
            acceptance: { justification: ..., approver_id: 7, review_date: 2027-06-30 }
```

**Diagrams.** Elements and flows become a ThreatAtlas diagram in the same format the
ThreatAtlas editor uses, so it opens and edits normally there.

- Elements without a `position: [x, y]` are laid out left to right along the data flows.
  Each trust boundary gets its own band and is sized to fit its members (or `size: [w, h]`).
- Positions changed in the ThreatAtlas editor are **kept** on re-import, unless the file
  sets them.
- Elements drawn in ThreatAtlas that aren't in the file are kept (listed as a note);
  `--prune` removes them.
- Element and flow IDs become the diagram's node IDs, so keep them stable: threats are
  attached to them.

**Risk acceptance.** `status: accepted` with an `acceptance` block requests an acceptance,
just as the ThreatAtlas UI does: ThreatAtlas records when it was accepted, and the approver
is notified. **Approving stays a human step** in ThreatAtlas; an import never approves
anything. `approver_id` is the approver's ThreatAtlas user ID.

**YAML tip.** Quote values that contain a comma inside `{ ... }`, for example
`description: "Limit attempts per card, device and IP address."`. Otherwise YAML splits
them into extra keys, and `tae` reports an unknown field.
