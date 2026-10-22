"""Module — a unit of source code in a programming language."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

#: The shape of ``language``: a lower-case name. A shape and not a closed list, because languages
#: are open-ended; ``library.language`` uses the same values (req-computing-core-module-2).
LANGUAGE_PATTERN = r"^[a-z][a-z0-9+#.-]{0,31}$"

#: A path relative to the root of the module's scope: not absolute (POSIX, Windows drive or UNC)
#: and with no ``..`` segment (req-computing-core-module-4). At least one character.
RELATIVE_PATH_PATTERN = r"^(?![/\\])(?![A-Za-z]:)(?!(?:.*[/\\])?\.\.(?:[/\\]|$)).+$"

PATH_SCHEMA: dict[str, Any] = {"type": ["string", "null"], "pattern": RELATIVE_PATH_PATTERN}
LANGUAGE_SCHEMA: dict[str, Any] = {"type": "string", "pattern": LANGUAGE_PATTERN}
COUNT_SCHEMA: dict[str, Any] = {"type": ["integer", "null"], "minimum": 0}


class Module(BaseModel):
    """A unit of source code in a language: a Python package, a Go package, a JavaScript module.

    A program loads modules; a package, a library or another module contains them; a module
    imports other modules. The node records that a module exists, where it sits relative to its
    scope, in what language and how large (``source_file_count``). It has no field that could hold
    source text, a function body or a secret: presence, never content, as ``crypto_provider``.

    ``path`` and ``source_file_count`` null mean not observed, never ``""`` or 0
    (req-computing-core-models, three states).

    Spec: specs/spec-computing-core-v0.md (req-computing-core-module).
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__module"
    ENTITY_NAME: ClassVar[str] = "Module"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A unit of source code in a programming language (a Python package, a Go package, a "
        "JavaScript module) with where it sits and how many source files it has. Programs load "
        "it, packages and modules contain it, modules import it. Holds no source text."
    )
    ENTITY_ICON: ClassVar[str] = "module"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "runtime"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scope", "name")
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "rectangle",
            "colors": {"fill": "#6FB5A8", "border": "#3F8276", "label": "#FFFFFF"},
        }
    }

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__module"}], "edges": [{"type": "CONTAINS_MODULE__computing_core"}]},
        {"nodes": [{"type": "computing_core__module"}], "edges": [{"type": "IMPORTS_MODULE__computing_core"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__program"}], "edges": [{"type": "LOADS_MODULE__computing_core"}]},
        {
            "nodes": [
                {"type": "computing_core__package"},
                {"type": "computing_core__library"},
                {"type": "computing_core__module"},
            ],
            "edges": [{"type": "CONTAINS_MODULE__computing_core"}],
        },
        {"nodes": [{"type": "computing_core__module"}], "edges": [{"type": "IMPORTS_MODULE__computing_core"}]},
    ]
    # A submodule is part of its parent; a program loading a module and an import are references.
    CONTAINMENT_EDGES: ClassVar[tuple[str, ...]] = ("CONTAINS_MODULE__computing_core",)

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scope": {"type": "string", "minLength": 1},
        "name": {"type": "string", "minLength": 1},
        "language": LANGUAGE_SCHEMA,
        "path": PATH_SCHEMA,
        "source_file_count": COUNT_SCHEMA,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "scope": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "name": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "language": {"validation": "jsonschema", "schema": LANGUAGE_SCHEMA},
        "path": {"validation": "jsonschema", "schema": PATH_SCHEMA},
        "source_file_count": {"validation": "jsonschema", "schema": COUNT_SCHEMA},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scope", "name", "language"]

    scope = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="What the module belongs to: the software unit that holds it, as it names itself (tap, vuln_mosaic).",
    )
    name = models.CharField(
        max_length=512,
        blank=True,
        default="",
        db_index=True,
        help_text="The module's own name in its language's naming: a dotted path for Python (tap_grid.gryphon).",
    )
    language = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="Implementation language, lower case (python, go, javascript, typescript, java, shell, c, rust).",
    )
    path = models.CharField(  # noqa: DJ001  (req-computing-core-module-4)
        max_length=1024,
        blank=True,
        null=True,
        default=None,
        help_text="Where it sits, relative to the root of its scope. Never absolute. Null = not observed.",
    )
    source_file_count = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=None,
        help_text="Number of source files, tests and generated files excluded. Null = not observed.",
    )

    class Meta(BaseModel.Meta):
        db_table = "computing_core__module"

    def get_name(self) -> str:
        return self.name

    def __str__(self) -> str:
        return self.get_name()
