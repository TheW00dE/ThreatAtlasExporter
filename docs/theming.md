# Report themes

A theme is the look of a report, kept separate from its content: fonts, colours, page
size and margins, the running header and footer, the cover layout, section numbering, a
watermark and the wording of headings, columns and status words. One theme file can be
shared by every report definition in an organisation, so a corporate layout is defined
once.

```bash
tae report init --theme corporate.yaml     # commented starting point
tae report labels --theme corporate.yaml   # every wording key and its current text
tae report schema --theme -f theme.schema.json   # for editor autocompletion
tae report check report.yaml               # checks the definition, theme, fonts and images
tae report build SNAPSHOT --theme corporate.yaml # or reference it from the definition
```

A definition uses a theme with `theme: ./corporate.yaml` (relative to the definition),
or defines one inline under `theme:`. `--theme` on the command line overrides both.
Values in the definition's `branding:` and `page_size` override the theme's, so one
theme can serve several organisations or classifications.

A complete, neutral example is in
[`examples/themes/example-corp.yaml`](../examples/themes/example-corp.yaml).

## Keys

Every key is optional. Relative paths are resolved against the theme file.

| Key | Meaning |
|---|---|
| `kind` | `report-theme` |
| `name` | Shown by `tae report check` |
| `branding` | `organisation`, `logo`, `classification`, `footer` |
| `fonts.body`, `fonts.headings` | `family`, and optional `files` (`regular`, `bold`, `italic`, `bold_italic`; TTF, OTF, WOFF or WOFF2) to embed. Without files the font must be installed where the PDF is rendered. |
| `fonts.size` | Base size in points (6–16) |
| `colors` | `primary`, `accent`, `text`, `secondary_text`, `muted`, `headings`, `table_header`, `table_header_text`, `table_stripe`, `border`, `cover_band`, `cover_text`, `classification` |
| `colors.severity` | `critical`, `high`, `medium`, `low`: badges, chart bars and diagram badges. Badge text turns black or white for contrast. |
| `colors.matrix` | Risk-matrix cell colours; default: lighter severity colours |
| `page.size` | `A4`, `A3`, `A5`, `Letter`, `Legal`, or `[width, height]` such as `[210mm, 297mm]` |
| `page.margins` | `top`, `right`, `bottom`, `left` |
| `header`, `footer` | `left`, `center`, `right` text; see below |
| `cover.layout` | `band` (coloured band), `plain`, or `image` (full-page `background_image`) |
| `cover.band_height`, `cover.logo_position` | Band height; logo `left`, `center` or `right` |
| `cover.facts` | List of `[label, value]` rows; values may use placeholders |
| `cover.show_generated_by` | The tool/snapshot line at the bottom of the cover |
| `numbering` | Number sections 1, 2, 3… (default `true`) |
| `watermark` | `text` (e.g. DRAFT), `color`, `opacity`; printed on every page |
| `labels` | Replacement wording, see below |
| `extra_css` | Stylesheet appended after the built-in one |

Colours are hex (`#0f4c5c`), lengths need a unit (`mm`, `cm`, `in`, `pt`, `px`).

## Header and footer

Each has three slots. Text may use `{{ product.name }}`, `{{ title }}`, `{{ subtitle }}`,
`{{ organisation }}`, `{{ classification }}`, `{{ footer }}` (organisation · footer
text), `{{ document.id }}`, `{{ document.version }}`, `{{ report_date }}` and any other
product field, plus `{page}` and `{pages}` for page numbers. `""` leaves a slot empty;
a slot that is left out keeps its default:

```yaml
header: {left: "{{ product.name }} — {{ title }}", center: "{{ classification }}", right: ""}
footer: {left: "{{ footer }}", center: "", right: "Page {page} of {pages}"}
```

The center header slot is printed in the classification colour. When validation fails
and the report is annotated, the right header slot shows a warning instead.

## Wording

`labels` replaces built-in text: section titles (`section.threat_table`), table columns
(`column.mitigation`), field names (`field.report_date`, `product.owner_name`), headings
inside sections, axis names, severity words (`severity.high`) and status words
(`status.mitigated`; other `status.<value>` keys are allowed too). Unknown keys are
errors, so typos are caught. `tae report labels` lists every key:

```yaml
labels:
  section.threat_table: Bedrohungen
  column.threat: Bedrohung
  severity.high: hoch
  status.mitigated: behandelt
```

Longer explanatory sentences are not labels; change those with a template override
(see [report-definition.md](report-definition.md#custom-templates)). Set the
definition's `language` to match, for hyphenation and the PDF's language tag.

## Safety

Themes are often shared, so every value that reaches the PDF is checked: colours,
lengths and font names must match strict patterns, header/footer and label text is
escaped, font and image files are checked by content and size (fonts 8 MB, cover images
4 MB, logos 2 MB), and nothing is fetched from the network (`extra_css` can't load remote
files either; use `data:` URIs for images).

## Brand assets

Use only fonts, logos and colours you are licensed and authorised to use. Corporate
fonts are often licensed per installation; check whether embedding them in PDFs is
allowed, or install them on the rendering machine and leave out `files`.
