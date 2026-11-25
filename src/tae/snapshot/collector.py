"""Pull one product's complete threat-model data into a :class:`Snapshot`."""

from __future__ import annotations

import logging
from collections.abc import Callable

from tae.client import ThreatAtlasClient
from tae.client.errors import NotFound, ThreatAtlasError
from tae.models.api import Product
from tae.snapshot.model import Snapshot, SnapshotMeta

log = logging.getLogger(__name__)

Progress = Callable[[str], None]


class ProductNotFound(ThreatAtlasError):
    """No product matches the given ID or name."""


def resolve_product(client: ThreatAtlasClient, ref: str) -> Product:
    """Find a product by numeric ID or by exact (case-insensitive) name."""
    ref = ref.strip()
    if ref.isdigit():
        try:
            return client.products.get(int(ref))
        except NotFound:
            raise ProductNotFound(f"No product with ID {ref} (or you don't have access to it)") from None
    matches = [p for p in client.products.list() if p.name.casefold() == ref.casefold()]
    if not matches:
        raise ProductNotFound(f"No product named {ref!r}. Run `tae products list` to see product names.")
    if len(matches) > 1:
        ids = ", ".join(str(p.id) for p in matches)
        raise ProductNotFound(f"Several products are named {ref!r} (IDs {ids}). Use the ID instead.")
    return matches[0]


def collect(client: ThreatAtlasClient, product: Product, progress: Progress | None = None) -> Snapshot:
    """Fetch the product's diagrams, threat models, threats and mitigations."""
    say = progress or (lambda _msg: None)

    say("Fetching frameworks")
    frameworks = client.frameworks.list()

    say(f"Fetching diagrams for {product.name}")
    diagrams = client.diagrams.list(product_id=product.id)
    # The list endpoint can omit heavy fields on some versions; fetch each diagram
    # individually when its data is missing so diagrams are always complete.
    diagrams = [d if d.diagram_data is not None else client.diagrams.get(d.id) for d in diagrams]

    models = []
    diagram_threats = []
    diagram_mitigations = []
    for diagram in diagrams:
        say(f"Fetching threat models, threats and mitigations for diagram {diagram.name!r}")
        models.extend(client.models.list(diagram_id=diagram.id))
        diagram_threats.extend(client.diagram_threats.list(diagram_id=diagram.id))
        diagram_mitigations.extend(client.diagram_mitigations.list(diagram_id=diagram.id))

    try:
        pulled_by: str | None = client.users.me().username
    except ThreatAtlasError:
        pulled_by = None

    snapshot = Snapshot(
        meta=SnapshotMeta(source_url=client.base_url, pulled_by=pulled_by),
        product=product,
        frameworks=frameworks,
        diagrams=diagrams,
        models=models,
        diagram_threats=diagram_threats,
        diagram_mitigations=diagram_mitigations,
    )
    log.info(
        "Pulled product %s: %d diagrams, %d models, %d threats, %d mitigations",
        product.id,
        len(diagrams),
        len(models),
        len(diagram_threats),
        len(diagram_mitigations),
    )
    return snapshot
