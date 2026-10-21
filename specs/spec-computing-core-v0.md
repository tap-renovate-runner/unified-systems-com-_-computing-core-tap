# Computing Core Plugin Specification

## Philosophy

The Computing Core plugin provides the vendor-neutral primitives needed to describe modern computing systems above hardware and below higher-level cloud-provider and application-domain abstractions. It is the layer where TAP begins to talk about virtual machines, containers, operating systems, filesystems, interfaces, IP addressing, ports, processes, programs, and network connections in a way that applies across cloud and on-prem environments.

The demarcation line for v0 is intentional. This plugin starts above physical hardware and below provider-specific infrastructure modeling. It should not try to describe chassis, disks, routers, switches, or specialized cloud constructs in provider-native terms. It should also avoid prematurely collapsing into product- or business-level concepts such as "service" and "application" where the project has not yet agreed on stable semantics.

The plugin favors durable primitives over convenience abstractions. If a concept is likely to remain meaningful across Linux hosts, containers, virtual machines, AWS, and on-prem environments, it belongs here. If it is provider-specific, orchestration-specific, or still semantically fuzzy, it should be deferred or modeled in a more specific plugin.

Networking is an especially important part of this layer. v0 should model the stable pieces of IP-based networking that are useful for graph traversal and system understanding without overcommitting to packet-level or datagram-level modeling. That means durable endpoint and session concepts now, with richer flow and protocol work later.

## Goals

|    |              |                                                                 |
| :---: | ---       | ---                                                             |
| 1. | Vendor-Neutral | Models capture generic computing and IP-networking primitives rather than provider-specific resources |
| 2. | Durable      | v0 prioritizes concepts likely to survive across environments and future plugins |
| 3. | Expressive   | Relationships favor semantically meaningful edge types over generic catch-all links |
| 4. | Dimensioned  | Every TAP-managed type in the plugin uses meaningful `tap.computing` default dimensions |
| 5. | Evolvable    | The plugin leaves clear room for deeper protocol, flow, and provider-integration work later |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-computing-core-scope | [Plugin Scope](#plugin-scope) | Proposed | Defines what Computing Core covers and excludes |
| req-computing-core-dimensions | [Dimension Strategy](#dimension-strategy) | Proposed | `tap.computing` dimensions and dimension-node experiment |
| req-computing-core-models | [Model Catalog](#model-catalog) | Proposed | Vendor-neutral model set for compute, storage, runtime, and networking |
| req-computing-core-ip | [IP Version Support](#ip-version-support) | Proposed | IPv4 and IPv6 are first-class supported capabilities |
| req-computing-core-ports | [Port Modeling](#port-modeling) | Proposed | Ports are first-class nodes with simple v0 state semantics |
| req-computing-core-interface | [Network Interface Modeling](#network-interface-modeling) | Proposed | `network_interface` MAC uses `null` for unobserved/not-applicable (partial-observation convention) |
| req-computing-core-tcp | [TCP Connection Modeling](#tcp-connection-modeling) | Proposed | TCP connections are modeled as nodes rather than edges |
| req-computing-core-application-flow | [Application Flow Modeling](#application-flow-modeling) | Implemented | `application_flow`: name and description only, keyless; `APPLICATION_FLOW_SOURCE` and `APPLICATION_FLOW_DESTINATION` (names deliberately not `<ACTION>_<OBJECT>`), open at both ends; the delete-with-its-ends rule is proposed, not built |
| req-computing-core-host | [Host Modeling](#host-modeling) | Implemented | One `host` type for every OS-bearing environment; physical-versus-virtual is `kind`; keyed `(realm, stable_id)` |
| req-computing-core-os-accounts | [OS Accounts And Groups](#os-accounts-and-groups) | Implemented | `os_user` / `os_group` live in one host's account database, keyed to it; `user` retired |
| req-computing-core-package | [Package Modeling](#package-modeling) | Implemented | `package`: one release of an apk/deb/rpm/pypi/npm package, keyed `(ecosystem, name, version)` |
| req-computing-core-source-package | [Source Package Modeling](#source-package-modeling) | Implemented | `source_package`: the source a binary package is built from (an apk origin), keyed `(ecosystem, name, version)`; every package draws `DERIVES_FROM_SOURCE_PACKAGE` to it |
| req-computing-core-library | [Library Modeling](#library-modeling) | Implemented | `library`: code built or vendored outside a package manager; whether it carries cryptography is an edge, not a column |
| req-computing-core-operating-system | [Operating System Modeling](#operating-system-modeling) | Implemented | `operating_system`: keyed `(os_id, version_id, build_id)` so a rolling distro's placeholder VERSION_ID does not merge builds |
| req-computing-core-crypto-provider | [Crypto Provider Modeling](#crypto-provider-modeling) | Implemented | `crypto_provider`: a cryptographic implementation found in an artifact and its FIPS-boundary disposition; no key material |
| req-computing-core-inventory-edges | [Software Inventory Edges](#software-inventory-edges) | Implemented | `INSTALLS_PACKAGE`, `DERIVES_FROM_SOURCE_PACKAGE`, `SHIPS_LIBRARY`, `LOADS_LIBRARY`, `RUNS_OPERATING_SYSTEM`, `CARRIES_CRYPTO_PROVIDER`; all references |
| req-computing-core-runtime-edges | [Runtime Edges](#runtime-edges) | Implemented | `RUNS_PROGRAM` (any node runs a program) and `RUNS_IMAGE` (any node runs a container-kind host, the image host); open source, references |
| req-computing-core-package-dependency | [Package Dependencies](#package-dependencies) | Implemented | `REQUIRES_PACKAGE`: the dependency links an SBOM lists between packages; a reference, no properties |
| req-computing-core-program-package | [Program Root Package](#program-root-package) | Implemented | `RUNS_PACKAGE`: the package whose code is the program itself, the root of the program's dependency closure; a reference, no properties, drawn by whoever knows it |
| req-computing-core-program-package-declared | [Declared Program Roots](#program-root-package) | Backlog | The SBOM generator declares each image's program roots and the parser draws `RUNS_PACKAGE` from them |
| req-computing-core-program-key | [Program Key Use](#program-key-use) | Implemented | `USES_KEY`: a program uses this private key, public key or file (a TLS key a server reads); a reference, no properties |
| req-computing-core-sbom-document | [SBOM Document](#sbom-document) | Implemented | `sbom_document`: the record that one SBOM existed (content digest, revision lineage, signer), never its body; `DESCRIBES_HOST` |
| req-computing-core-sbom-parse | [SBOM Parser](#sbom-parser) | Implemented | A pure, Django-free CycloneDX 1.4-1.7 parser: bytes in, a typed batch of packages, libraries, source packages, the operating system and edges out; fails closed |
| req-computing-core-sbom-vulns | [SBOM Vulnerabilities](#sbom-vulnerabilities) | Implemented | `parse_cyclonedx_vulnerabilities`: the pure, verified-only reader of a scanned CycloneDX document's `vulnerabilities[]` into neutral records (vulnerabilities, matches against the nodes `parse_cyclonedx` makes, detecting tools); names no compliance vocabulary |
| req-computing-core-sbom-build | [SBOM Builder](#sbom-builder) | Implemented | The mirror of the parser: a throwaway CycloneDX document built from packages on the grid, carrying what a scanner matches on |
| req-computing-core-protocols | [Protocol Scope](#protocol-scope) | Proposed | v0 stops just above layer four with generic application protocol modeling |
| req-computing-core-edges | [Edge Types](#edge-types) | Proposed | Expressive edge family for structural and runtime relationships |
| req-computing-core-reference | [Reference Data](#reference-data) | Proposed | Dimension nodes and any seed taxonomy data |
| req-computing-core-validation | [Plugin Validation](#plugin-validation) | Proposed | Structural validation now; deeper levels encouraged before publication |
| req-computing-core-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | Explicitly deferred concerns |

### Plugin Scope
----
RID: `req-computing-core-scope`

Status: `Proposed`

The Computing Core plugin models modern computing infrastructure primitives above hardware and below provider-specific cloud resources and higher-level product/application abstractions.

#### Implementation

The plugin covers:

- compute runtime units such as virtual machines and containers
- host/runtime environment such as operating systems
- storage primitives such as filesystems and files
- runtime execution primitives such as programs and processes
- network attachment primitives such as interfaces, IP addresses, subnets, and ports
- transport/session primitives such as TCP connections
- generic application-protocol concepts above transport but below concrete protocols like HTTP or DNS

The plugin excludes in v0:

- physical hardware
- provider-native infrastructure resources such as VPCs, EBS volumes, Elastic IPs, and AWS subnets
- deep network packet or hop modeling
- concrete application protocols such as HTTP, TLS, DNS, SSH, and SMTP
- unstable higher-level concepts such as "service" and "application" until those semantics are better defined

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-scope-1 | Above Hardware | Proposed | The plugin starts at the virtual-machine/container layer rather than modeling physical hardware. | `host` is in scope under this reading: it is the OS-bearing environment ("host/runtime environment such as operating systems" above) and carries no CPU, chassis, NIC or serial, so a workstation `host` is not hardware modelling (computing-core#8). |
| req-computing-core-scope-2 | Vendor Neutral | Proposed | v0 models generic primitives rather than provider-native resources. | |
| req-computing-core-scope-3 | Stable Semantic Focus | Proposed | Ambiguous higher-level concepts are deferred until TAP defines them more clearly. | |

#### Future

Later work may split networking and protocol concerns into dedicated plugins or use additional dimensions to distinguish networking subdomains while preserving Computing Core as the foundational generic layer.

### IP Version Support
----
RID: `req-computing-core-ip`

Status: `Proposed`

IPv6 is a first-class supported capability alongside IPv4.

#### Implementation

The plugin should be designed so IPv4 and IPv6 work naturally anywhere generic IP concepts appear. At minimum, this includes:

- `ip_address`
- `ip_subnet`
- `network_interface` relationships to addresses
- any port and connection modeling that depends on address identity

IPv6 support should not be treated as an afterthought or left to provider-specific plugins. If a generic computing/networking concept can apply to IP addressing, the v0 design should assume both IPv4 and IPv6 are in scope unless there is a concrete reason to defer a detail explicitly.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-ip-1 | IPv4 And IPv6 Supported | Proposed | Generic IP primitives support both IPv4 and IPv6. | |
| req-computing-core-ip-2 | Interface Relationships Support IPv6 | Proposed | Interface-to-address relationships accommodate IPv6 without special-case redesign. | |
| req-computing-core-ip-3 | No IPv4-Only Assumptions | Proposed | v0 model design avoids accidental IPv4-only assumptions in generic computing primitives. | |

### Dimension Strategy
----
RID: `req-computing-core-dimensions`

Status: `Proposed`

Every TAP-managed type in the plugin uses meaningful `tap.computing` default dimensions, and the plugin experiments with explicit dimension nodes to document those categories.

#### Implementation

The plugin uses `tap.computing` as its core domain dimension key. Each model and edge type should declare a category value meaningful to the part of the computing stack it represents, for example:

- `host`
- `runtime`
- `storage`
- `network`
- `protocol`
- `identity`

These values should remain small, reviewable, and durable in v0. The purpose is not to create a deep ontology on day one, but to force the plugin to locate each type within the computing domain explicitly.

The plugin also experiments with explicit dimension nodes representing those categories, including explanatory descriptions of what each category means and why it exists. This is intended as a practical trial of TAP's optional dimension-node concept rather than a claim that the full dimension-node design is complete.

##### Web-Native Marker (future `web_core` seam)
----
RID: `req-computing-core-web-marker`

The `web_host` and `web_document` types were added under demo-time scope creep
above the plugin's intended "below service/application" line. To keep that
creep cleanly reversible, every web-native type (and any future web-native edge) carries a second
dimension `tap.web: native` alongside its `tap.computing` stack-layer value.
This is an explicit future seam: a later `web_core` plugin can lift every
web-native type and edge in one shot by matching on the `tap.web` key, without
having to disentangle them from the genuine computing primitives. `tap.web`
also previews that plugin's eventual domain dimension key.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-dimensions-1 | Default Dimensions Required | Proposed | Each model declares meaningful `DEFAULT_DIMENSIONS` using the `tap.computing` key. | |
| req-computing-core-dimensions-2 | Edge Default Dimensions Required | Proposed | Each edge definition declares meaningful `default_dimensions` using the `tap.computing` key. | |
| req-computing-core-dimensions-3 | Small Category Set | Proposed | v0 uses a small, reviewable set of `tap.computing` values rather than ad hoc proliferation. | |
| req-computing-core-dimensions-4 | Dimension Node Experiment | Proposed | The plugin seeds dimension nodes explaining the chosen categories and their intent. | |
| req-computing-core-web-marker-1 | Web-Native Dual Tag | Proposed | `web_host`/`web_document` and any web-native edges carry `tap.web: native` alongside their `tap.computing` value, so a future `web_core` split is a one-shot lift by `tap.web`. | The two web edges were retired 2026-10-02 (computing-core#25). |

#### Open Questions

Should `tap.computing` values be a tightly closed vocabulary enforced by validation, or should the plugin start with conventions only and tighten later once query patterns emerge?

### Model Catalog
----
RID: `req-computing-core-models`

Status: `Proposed`

The plugin declares vendor-neutral TAP-managed models organized by compute, runtime, storage, and networking concerns.

#### Implementation

The initial v0 model set is:

| Category | Models | Notes |
| --- | --- | --- |
| Compute | `host`; planned: `virtual_machine`, `container` | `host` is built (one type, `kind` says which environment); the two planned rows can still be minted as specialisations if a consumer needs them |
| Runtime | `operating_system`, `program`, `process`; built since 2026-10-14: `operating_system`, `package`, `library`, `crypto_provider`; since 2026-10-15 `source_package` | Operating context plus executable/runtime units, and the software inventory of a host: see [Package](#package-modeling), [Source Package](#source-package-modeling), [Library](#library-modeling), [Operating System](#operating-system-modeling), [Crypto Provider](#crypto-provider-modeling) |
| Storage | `storage_volume`, `filesystem`, `file` | Generic storage abstraction plus mounted and contained data |
| Networking | `network_interface`, `ip_address`, `ip_subnet`, `port` | Stable IP-stack primitives |
| Transport/Protocol | `tcp_connection`, `application_protocol`; built since 2026-10-19: `application_flow` | Session node plus protocol abstraction above layer four, and the aggregate of traffic between a source and a destination: see [Application Flow](#application-flow-modeling) |
| Identity | `os_user`, `os_group` | Accounts and groups defined in one host's account database. A person is `identity_core__human`, not a computing_core type; `user` was retired 2026-10-08 |
| Web (web-native) | `web_host`, `web_document` | Internet hosts and URL-addressed documents; carry the `tap.web` marker (see below) |

Definitions and intent:

- **virtual_machine**: a guest compute environment managed above physical hardware
- **container**: a containerized execution environment
- **operating_system**: the OS environment associated with a virtual machine or container host; built, keyed by os-release `ID`, `VERSION_ID` and a build identifier ([Operating System Modeling](#operating-system-modeling))
- **package**: one release of a package a package manager installs ([Package Modeling](#package-modeling))
- **source_package**: the source a binary package is built from; an apk origin, a deb `Source:`, an rpm source RPM ([Source Package Modeling](#source-package-modeling))
- **library**: code an application imports or links that was built or vendored outside a package manager ([Library Modeling](#library-modeling))
- **crypto_provider**: a cryptographic implementation found in an artifact, with its FIPS-boundary disposition ([Crypto Provider Modeling](#crypto-provider-modeling))
- **program**: the execution of an application concept that may spawn multiple processes and rely on executable/configuration/data files
- **process**: a concrete runtime process
- **storage_volume**: a generic storage backing unit such as a block-backed logical volume
- **filesystem**: a mounted or mountable filesystem namespace
- **file**: a filesystem object tracked as a durable artifact when meaningful
- **network_interface**: an operating-system-level interface such as `eth0`, `eth1`, or virtual equivalents
- **ip_address**: a generic IPv4 or IPv6 address
- **ip_subnet**: a generic IPv4 or IPv6 subnet or prefix
- **port**: a transport endpoint identified primarily by port number and transport family
- **tcp_connection**: a TCP session represented as a node
- **application_flow**: a conceptual aggregate of traffic between a source and a destination, a node the sender and receiver hang from by two edges ([Application Flow](#application-flow-modeling))
- **application_protocol**: a generic protocol concept that rides above transport and can later branch into specific protocols
- **host**: a computing environment that runs an operating system and executes programs (workstation, server, VM, container, CI runner, cloud dev environment); see [Host Modeling](#host-modeling)
- **os_user**: an account in one host's own account database (`/etc/passwd`, a Windows local account); not a person. See [OS Accounts And Groups](#os-accounts-and-groups)
- **os_group**: a group in one host's own account database (`/etc/group`, a Windows local group)
- **web_host**: a named internet host that serves content over HTTP(S), identified by hostname (e.g. `cisa.gov`). For external/unmanaged hosts this models the serving origin, not its internal compute.
- **web_document**: a document retrievable at a URL over HTTP(S) (e.g. the CISA KEV catalog). Distinct from `file`, which is a filesystem object keyed by path; a web document is network-delivered content addressed by URL.

Relationship simplification for v0:

- `program` runs on `operating_system`
- `operating_system` runs on `virtual_machine` or `container`

This is intentionally simpler than trying to model every possible runtime or orchestration path on the first pass.

No type carries a free-form `configuration` field. Eight types (`network_interface`, `ip_address`, `port`,
`tcp_connection`, `program`, `file`, `public_key`, `private_key`) had one from the July 2026 monorepo
extraction, but no collector fills it, and a verbatim record with no reader is only a place for secret
material (a private key's, a config file's contents) or personal data to collect, so only promoted columns
are stored. Migration `0004_drop_unused_configuration` removed it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-models-1 | Generic Primitive Set | Proposed | v0 declares a vendor-neutral set of computing primitives rather than provider-native resources. | |
| req-computing-core-models-2 | Program Included | Proposed | The model set distinguishes `program` from `process` and leaves higher-level `application` semantics deferred. | |
| req-computing-core-models-3 | Storage Volume Included | Proposed | The model set includes a generic `storage_volume` abstraction to support later provider integration. | |
| req-computing-core-models-4 | Application Deferred | Proposed | The plugin does not define a generic `application` or `service` model in v0. | |
| req-computing-core-models-5 | User Is Generic Person | Deprecated | Withdrawn 2026-10-08 (computing-core#27): a person is `identity_core__human`, and the generic `user` type duplicated it. The type is retired, not redefined; see `req-computing-core-os-accounts-5`. | |
| req-computing-core-models-6 | Web-Native Primitives | Proposed | The plugin models `web_host` (internet host serving over HTTP(S)) and `web_document` (URL-addressed document), distinct from `file`. Both carry the `tap.web` marker. | Demo-time scope creep above the vendor-neutral line; see `req-computing-core-web-marker`. |
| req-computing-core-models-7 | No Free-Form Record | Implemented | No type declares `configuration`, and a `create_node` write carrying it is refused. | `tests/test_no_free_form_record.py` |

#### Open Questions

- Whether `operating_system` should represent a concrete installed OS instance, an OS family/version descriptor, or support both patterns may need additional design work during implementation.
- Whether `container` should always imply an underlying operating-system context directly or only through its host/runtime environment may need refinement once real container observations are modeled.

### Port Modeling
----
RID: `req-computing-core-ports`

Status: `Proposed`

Ports are first-class nodes whose primary identity is transport plus port number.

#### Implementation

The important durable field on a port is its port number. In v0, the plugin should support:

- well-known and registered server-side ports
- client-side ephemeral or unknown ports: the *unknown number* is `port_number = null` (grid convention); the *ephemeral signal* (number unknown but known to be ephemeral) is a separate observation, deferred to a future `is_ephemeral`/`role` field rather than overloaded onto `null` or a sentinel — see Future
- a simple port state field distinct from the numeric port identity

The v0 port state vocabulary should stay intentionally small:

- `listening`
- `bound`
- `connected`
- `closed`

This avoids overloading the port number while leaving room to express whether a port is merely bound, actively listening, or participating in a connection.

Ports should support more than one observational shape in v0:

- a structural shape where a port is attached to a known network interface
- an observational shape where a port is known to be available at an IP address even when the interface is not known

This is important because some data sources, such as network scanners, may observe only an IP address, port, and program path. The model should allow those observations without forcing creation of pseudo, assumed, or unknown network-interface nodes.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-ports-1 | Port Node Exists | Proposed | Ports are modeled as nodes, not only as integers embedded in other records. | |
| req-computing-core-ports-2 | Ephemeral Convention | Proposed | `port_number = null` means the port number is unobserved. The ephemeral/client-role signal is carried by a separate (future) `is_ephemeral`/`role` field, not overloaded onto `null`; "match any port" is a rule concept, out of scope for observation Port nodes. | Applies grid `req-grid-node-observation` (`null` = unobserved); see Future. |
| req-computing-core-ports-3 | Separate Port State | Proposed | Port state is modeled separately from the port number. | |
| req-computing-core-ports-4 | Interface Optional For Observation | Proposed | A port may be related directly to an IP address even when no concrete network interface is known. | |

#### Future
- **Ephemeral / role signal (`is_ephemeral` or `role`).** Disentangle the pre-convention `port_number = null` overload (originally "wildcard / ephemeral / unknown"). Under the grid convention `null` means only *number unobserved*; the positive fact "this is a client-side ephemeral port" — true even when the number is unknown — belongs in its own field. Add a nullable `is_ephemeral` boolean, or a richer `role` enum (`client` / `server` / `listening`) with ephemerality derivable, deciding bool-vs-role when built. The new field follows the grid field-observation convention itself (nullable = unobserved, carrying its own `x-tap-absence`). "Match any port" wildcard semantics, if ever needed, live on a rule/policy node, not on an observed Port. Named, not built.

### Network Interface Modeling
----
RID: `req-computing-core-interface`

Status: `Proposed`

A `network_interface` models an operating-system-level interface (`eth0`, a virtual equivalent). Its hardware address is carried by `mac_address`, which is a concrete application of the grid-wide field-observation convention (`tap_grid` `req-grid-node-observation`): a data source may observe an interface without its MAC — a scanner that sees the interface name but never captures the hardware address — so the field uses `mac_address = null` to mean **"hardware address unobserved or not applicable"**, distinct from `""`. This is the same convention `port_number = null` applies (`req-computing-core-ports-2`); both defer to the grid requirement for the full taxonomy, the FLIP known-vs-unknown-unknown hinge, and the lint-deviation rule.

`null` is therefore the deliberate "unobserved" representation for `mac_address` specifically; the interface's other string fields (`name`, `state`) use `default=""` because their empty case is a genuine empty string, not an unobserved one. The absence semantics are **declared**, not merely commented: `FIELD_CRUD_SCHEMA["mac_address"]["x-tap-absence"]` carries `null_default`, `empty_is_meaningful`, a `description`, and a Phase-2-reserved `not_applicable` clause (`permitted: true` — a loopback/virtual interface has no MAC by nature), and auto-publishes through `SERVICE_CRUD_SCHEMA` to external readers and Gryphon (grid `req-grid-node-observation-6`). Per the grid convention's DJ001 rule, the model field also carries `# noqa: DJ001  (req-computing-core-interface-1)` as the lint-silencer; the `x-tap-absence` annotation is the authoritative source of truth.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-interface-1 | MAC Unobserved Convention | Proposed | `mac_address = null` represents an interface whose hardware address was not observed or is not applicable, distinct from `""`. | Applies grid `req-grid-node-observation`; authorizes the model's `# noqa: DJ001  (req-computing-core-interface-1)`. |

### TCP Connection Modeling
----
RID: `req-computing-core-tcp`

Status: `Proposed`

TCP connections are modeled as nodes rather than direct edges.

#### Implementation

A TCP connection is represented as a node so TAP can attach:

- connection lifecycle state
- timing and observation metadata
- explanatory and dependency edges
- higher-layer protocol relationships

Edges are created in the direction of session creation:

- client port to TCP connection node
- TCP connection node to server port

This allows an `application_protocol` node to express that it relies on a specific TCP connection without collapsing transport and application flow into a single edge.

The v0 TCP connection state vocabulary should align with the classic RFC 793 lifecycle states rather than port states.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-tcp-1 | Connection Is Node | Proposed | A TCP connection is represented as a node. | |
| req-computing-core-tcp-2 | Directional Session Edges | Proposed | Session edges go from the client side to the connection node and from the connection node to the server side. | |
| req-computing-core-tcp-3 | Connection State Separate | Proposed | TCP lifecycle state lives on the connection, not on the port. | |
| req-computing-core-tcp-4 | Protocol Attachment Point | Proposed | Higher-layer protocol nodes may attach to the TCP connection node. | |

#### Future

Consider a future `udp_flow` model if real use cases emerge, and consider whether any later `ip_flow` concept should share that modeling direction. Deeper packet-hop or path modeling is intentionally deferred until TAP has a concrete need and a stable semantics for representing network hops.

### Application Flow Modeling
----
RID: `req-computing-core-application-flow`

Status: `Implemented`

An application flow is a node, `computing_core__application_flow`, with two edges: the sender points at it and it points at the receiver.

#### Implementation

The model has two fields, `name` and `description`, both strings and neither required. It is not a `tcp_connection`: a connection is a transport session some source system observes between two ports, and a flow is the aggregate a person names above it ("customers reach tap-web"), however many connections carry it.

**Keyless, on purpose.** The model declares `NATURAL_KEY = KEYLESS` with this reason, approved by George 2026-10-19 and kept verbatim: *An application flow is a conceptual aggregate of traffic between a source and a destination; no source system observes it, so it has no stable identifier to key on yet. A natural key will be declared when one is found.* A keyless type is not found again by its properties, so a writer that must re-find a flow carries its own stable entity id (seed data does); a second create is a second node, never a merge.

Two edges join it to its ends, both with the plain identity, no properties, `tap.computing: network`, and both references, not containment (no model lists either in `CONTAINMENT_EDGES`):

| edge | sentence |
| --- | --- |
| `APPLICATION_FLOW_SOURCE__computing_core` | `<sender> APPLICATION_FLOW_SOURCE <application_flow>` |
| `APPLICATION_FLOW_DESTINATION__computing_core` | `<application_flow> APPLICATION_FLOW_DESTINATION <receiver>` |

**The names break the `<ACTION>_<OBJECT>` form on purpose.** They are George's, they name the role an end plays in the flow rather than an action it takes, and the edge descriptions say so. They are not a precedent for other edges.

**Both ends of both edges are open.** Neither edge declares `sources` or `targets`: the sender and receiver are any node (a computer, a program, an aws_core resource), which is not enumerable, so the edge definition constrains nothing and `application_flow` as the other end is a convention the tests hold, not a check the grid makes.

**What "open" means in the grid today.** Core registers an edge's endpoint constraints only when it declares `sources` or `targets`; an edge that declares neither is registered as no constraint, grants nothing, and is permitted only between node types that do not declare their own edges. A type that does declare them closes its side, so `host` names both flow edges in its `OUTBOUND_EDGES` and `INBOUND_EDGES` (to and from `application_flow` only), and another plugin's type that declares its edges must do the same to send or receive a flow. A type that declares no edges (`program`, `tcp_connection`, and `aws_core__aws_ecs_container`, which declares none) needs nothing and must not be given declarations only to carry these edges: declaring them would close the type to every edge it does not list. Checked against `aws_core` v0.8.0 on 2026-10-19: task `RUNS_CONTAINER` container, container `RUNS_PROGRAM` program, program `RUNS_PROGRAM` program, container `RUNS_IMAGE` host, host `APPLICATION_FLOW_SOURCE` flow and flow `APPLICATION_FLOW_DESTINATION` program, and a container as flow sender, all pass the grid's edge validation.

**Delete rule, proposed and not built.** An application flow does not exist without its source and destination, so it should be deleted with either. The mechanism is deferred: this change builds no cascade, no hook and no change to `tap_grid`, and the edges are references until the mechanism is decided.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-application-flow-1 | Name And Description Only | Implemented | `application_flow` has the fields `name` and `description` and no other domain field; both are optional strings. | `tests/test_application_flow.py::TestApplicationFlow::test_it_holds_a_name_and_a_description_and_nothing_else` |
| req-computing-core-application-flow-2 | Keyless With George's Reason | Implemented | The type declares `NATURAL_KEY = KEYLESS` and the reason text of this section, verbatim; two creates with the same name are two nodes. | `::test_it_is_keyless_with_the_approved_reason`, `::test_two_flows_of_one_name_are_two_nodes` |
| req-computing-core-application-flow-3 | Source And Destination Edges | Implemented | `APPLICATION_FLOW_SOURCE__computing_core` joins a sender to a flow and `APPLICATION_FLOW_DESTINATION__computing_core` joins a flow to a receiver; neither declares `sources` or `targets`, so any node type is accepted at the open end; both carry the plain identity, no properties and `tap.computing: network`. | `::TestEdges::test_a_flow_joins_any_sender_to_any_receiver`, `::test_a_program_may_send_and_receive_a_flow_too`, `::test_the_flow_edges_are_open_at_both_ends_plain_and_not_containment` |
| req-computing-core-application-flow-4 | Icon And Display | Implemented | The type has `ENTITY_ICON = "application-flow"`, an 80x80 SVG shipped in the plugin that is a solid dark-blue (`#0B3D91`) disc with a white flow glyph and nothing outside the disc (the icon is the circle, transparent corners), and a default `tap_viz` display of shape `ellipse` with fill, border and label all `#0B3D91`. Edge styling (colour, width, arrowheads) is not declarable per edge type today: the manifest edge file has no display field and the graph panel styles every edge alike, so a layout does it. | `::TestApplicationFlow::test_it_has_an_icon_file_and_a_display` |
| req-computing-core-application-flow-5 | Registered In The Manifest | Implemented | The manifest registers the model and the two edges, and each edge slug equals its file name. | `::test_the_manifest_registers_the_type_and_the_flow_edges` |
| req-computing-core-application-flow-6 | Flow Deleted With Its Ends | Proposed | An application flow does not exist without its source and destination, so it is deleted with either. The mechanism is deferred: no cascade, hook or `tap_grid` change is built, and until it is, retiring a sender or receiver leaves the flow. | George's principle, 2026-10-19. Not built, and no issue is filed: the mechanism is the open question. |

### Host Modeling
----
RID: `req-computing-core-host`

Status: `Implemented`

A `host` is a computing environment that runs an operating system and executes programs. One durable type covers a workstation, a server, a virtual machine, a container, a CI runner and a cloud dev environment. Which of those it is is the `kind` attribute, not a separate type (computing-core#8).

#### Implementation

| field | meaning |
| --- | --- |
| `realm` | The authority that issued `stable_id`: `aws-ec2`, `github-runner`, `machine-id`, `assert` (an operator's own slug), and so on. |
| `stable_id` | The host's identifier within that realm: an instance id, a runner label set, the contents of `/etc/machine-id`, an operator slug. **Never the hostname.** |
| `name` | The display name, usually the hostname. |
| `kind` | One of `workstation`, `server`, `virtual_machine`, `container`, `ephemeral_runner`, `cloud_dev_environment`, `unknown`. `null` means not observed. `unknown` means someone looked and could not tell. |
| `os` | The operating system as reported (`linux`, `macOS 15.6`). It can become its own `operating_system` node later without migrating this field. |
| `ephemeral` | `true` when nothing survives between uses, as on a hosted CI runner. `null` means not observed. |

**Why one type with a `kind`, not `virtual_machine` plus `container`.** At collection time a collector often cannot tell which environment it is looking at. A hosted runner is a VM, a self-hosted runner may be bare metal, and a Codespace is a container. Four types would force the collector to guess. One type with an honest `kind`, including `unknown`, does not.

**Why `(realm, stable_id)` is the natural key.** A host has no single global identifier. Each authority that observes it issues its own, so the key names the authority and the identifier together. The hostname is not used because operators change it and two machines can share it. One machine seen through two realms (an EC2 instance id and its `/etc/machine-id`) becomes two `host` nodes. Joining them is a separate assertion and is never inferred. That is the multi-observer cost, and it is accepted.

**No identity module.** #8 proposed `tap_plugin/computing_core/identity.py`, which would derive ids with `uuid5`. That proposal predates `req-grid-entity-natural-key`. Ids are now always assigned, and a collector names nodes by batch-local refs that the declared natural key resolves. So a plugin that emits a `host` declares nothing beyond the payload, and no module derives ids.

**Delete tree.** A host contains the accounts and groups its own account database defines. `CONTAINMENT_EDGES = (DEFINES_OS_USER, DEFINES_OS_GROUP)`, so retiring a host with `cascade="contained"` retires them too.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-host-1 | One Host Type | Implemented | `computing_core__host` exists with `tap.computing: host`. Its natural key is `(realm, stable_id)`. A rename of `name` leaves the row findable by the generated search. | `tests/test_host_and_os_accounts.py::TestHost` |
| req-computing-core-host-2 | Kind Is Closed, Null Is Unobserved | Implemented | `kind` accepts only the seven values above or `null`. `null` (not observed) is distinct from `unknown` (observed but indeterminate). | Authorizes the model's `# noqa: DJ001  (req-computing-core-host-2)`. `tests/test_host_and_os_accounts.py::TestHost::test_kind_is_a_closed_vocabulary` |
| req-computing-core-host-3 | Host Contains Its Local Principals | Implemented | Retiring a host with `cascade="contained"` retires the `os_user` and `os_group` nodes it defines. | `tests/test_host_and_os_accounts.py::TestEdges::test_a_host_retires_its_accounts_and_groups` |

#### Not Yet Built

These are from #8 and stay open there: `OWNS_HOST` (it was drawn from the retired `user`, so it would now come from `identity_core__human`, which is a cross-plugin question), `HOLDS_PRIVATE_KEY` (`host` -> `private_key`), and `KEY_PAIR`. Collectors must also avoid the node explosion #8 warns about: a hosted runner is one `host` per label set, not one per job.

### OS Accounts And Groups
----
RID: `req-computing-core-os-accounts`

Status: `Implemented`

`os_user` and `os_group` are the accounts and groups defined in one host's own account database: a Linux `/etc/passwd` or `/etc/group` entry, or a Windows local SAM account or local group. They follow the pattern every other account type on the grid follows. A person is `identity_core__human`, and each account that person holds points at them with `HELD_BY_HUMAN__identity_core`. That edge's source side is open (wildcard), so an `os_user` can draw it without identity_core naming this plugin and without a new edge.

#### Implementation

**Natural keys.** Both types use `(host_realm, host_stable_id, local_id)`. The first two are the defining host's own key, stored as columns so the generated search can filter on them; dimensions cannot do that job (`req-grid-entity-natural-key-10`). `local_id` is the identifier the account database itself uses to tell entries apart and does not re-issue:

- **Windows: the SID.** A rename keeps the SID, so renaming `Administrator`, a common hardening step, leaves one node with a history of names. A builtin group's well-known SID (`S-1-5-32-544`) is the same on every machine, which is one reason the host is part of the key.
- **POSIX: the login name or group name, not the uid or gid.** POSIX lets two names share one id (`root` and `toor`), so keying on the number would merge two accounts. A batch that saw both would also fail as a duplicate. A freed uid is re-issued to the next account created, so a uid key would hand an old account's history and edges to a new one. A rename (`usermod -l`, `groupmod -n`) therefore produces a new node. The old node retires once its host's collector no longer observes it, and its history and edges do not carry over. That matches the account database's own behaviour, where every file naming the old login stops matching.

On POSIX, `local_id` and `name` hold the same string. They are two facts that coincide on that platform: `local_id` is identity and `name` is the reported display name. On Windows they differ.

A directory account or group (Active Directory, LDAP) that a host only resolves is not an `os_user` or `os_group`. The directory defines it, not the host.

**Edges.**

| edge | sentence | kind |
| --- | --- | --- |
| `DEFINES_OS_USER__computing_core` | `<host> DEFINES_OS_USER <os_user>` | containment |
| `DEFINES_OS_GROUP__computing_core` | `<host> DEFINES_OS_GROUP <os_group>` | containment |
| `MEMBER_OF_GROUP__computing_core` | `<os_user> MEMBER_OF_GROUP <os_group>` | reference. Optional property `primary` (bool): `true` when the membership comes from the account's primary-group field (`/etc/passwd`'s gid), `false` when the group's member list names the account |
| `HELD_BY_HUMAN__identity_core` (identity_core's) | `<os_user> HELD_BY_HUMAN <human>` | reference, an assertion. Not owned here |

The containment edges point from host to account because the host's account database is what defines the entry, and because cascade follows outbound edges only. Endpoint rules are declared on the models as well as in the edge files (`OUTBOUND_EDGES` on `host` and `os_user`, `INBOUND_EDGES` on `os_user` and `os_group`). Under the grid's permission union, an undeclared node accepts every edge type, so the edge files alone would not hold.

**`user` is retired, not redefined.** `computing_core__user` described "a human who interacts with computing systems", which is `identity_core__human`, and was keyed on a display name. It was removed in four places:

- the manifest
- the model, its tests and its table: migration `0007_retire_user_rows` deletes every `user` entity, its typed row, each edge incident to one, and each such edge's own spine row; `0008_delete_user` drops the table
- core's retired-type registry, called from `ready()`, so a seed from an older pin that still carries a `user` node is stripped at the seeding boundary with the reason, instead of failing the boot
- this spec (`req-computing-core-models-5`, Deprecated)

The only consumer was samsite's people seed, which moves to `identity_core__human` in its own change (samsite-tap#33).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-os-accounts-1 | Keyed To The Host | Implemented | `os_user` and `os_group` declare `NATURAL_KEY = (host_realm, host_stable_id, local_id)`. One name on two hosts is two nodes. | `tests/test_host_and_os_accounts.py::TestOsUser::test_same_name_on_two_hosts_is_two_accounts` |
| req-computing-core-os-accounts-2 | SID Survives A Rename | Implemented | A Windows account renamed in place is found again by its SID. | `::TestOsUser::test_windows_account_keeps_its_sid_across_a_rename` |
| req-computing-core-os-accounts-3 | A Shared uid Is Two Accounts | Implemented | Two POSIX names with one uid are two nodes. | `::TestOsUser::test_two_posix_names_sharing_one_uid_are_two_accounts` |
| req-computing-core-os-accounts-4 | Membership Is A Reference | Implemented | `MEMBER_OF_GROUP` connects only `os_user` -> `os_group` and refuses undeclared properties. Retiring a group ends the membership and leaves the account. | `::TestEdges` |
| req-computing-core-os-accounts-5 | User Retired | Implemented | The manifest defines no `computing_core__user`. Core's retired-type registry carries the reason. An older seed's `user` node is stripped rather than failed. Migration `0007` deletes `user` rows and their edges and keeps everything else. | `tests/test_retired_user.py` |
| req-computing-core-os-accounts-6 | Held By A Human | Implemented | An `os_user` can be the source of `HELD_BY_HUMAN__identity_core` with no change to either plugin's edge set. | Verified on a stack with identity_core installed. Not in this suite, because computing_core does not depend on identity_core. |

### Package Modeling
----
RID: `req-computing-core-package`

Status: `Implemented`

A `package` is one release of something a package manager installs: an apk of a Wolfi image, a deb or rpm, a Python or npm distribution. It is the row an SBOM lists and the unit a vulnerability scanner matches an advisory against (computing-core#33).

#### Implementation

| field | meaning |
| --- | --- |
| `ecosystem` | The package-URL type of the manager: `apk`, `deb`, `rpm`, `pypi`, `npm`, `generic`. Lower-case, an open vocabulary (the purl spec adds types). Identity. |
| `name`, `version` | As the package manager reports them. Identity. |
| `architecture` | `x86_64`, `aarch64`, `noarch`; empty where the ecosystem has none. The value of the observation that last wrote it. Not identity. |
| `purl`, `cpe`, `license` | CycloneDX component fields of the same names. `license` holds an SPDX expression. `purl` is kept whole, qualifiers included (`arch`, `distro`, `upstream`); nothing trims or rebuilds it. |
| `cpe_candidates` | The other CPE 2.3 names a document lists for the same component (Syft writes them as repeated `syft:cpe23` properties: `libssl3` carries three beside its `cpe`). A list of strings, each starting `cpe:2.3:`, never repeating `cpe`; empty where the document lists none. Not identity. |
| `source_document` | Which document the most recent observation came from: `sbom`, `uv.lock`, `supplemental`. Not identity. |

The names follow CycloneDX components so an SBOM row maps in without translation. CycloneDX `bom-ref` is not stored: it is a document-local handle, not identity. File hashes are not stored: no inventory column needs them, and the SBOM remains the place that carries them.

**Why `(ecosystem, name, version)` and not the purl.** A purl for an apk carries `arch` and `distro` qualifiers that differ between two scans of the same package. Identity is the three facts every ecosystem has; the qualifiers that matter are columns. Two architectures of one release are one node, because a vulnerability attaches to the release and the inventory counts it once. The cost is that `architecture` and `source_document` hold the last observation's value when two documents disagree.

**A package is not a library.** A package may bundle many things; a `library` is code built or vendored outside a package manager. A package that ships a library draws `SHIPS_LIBRARY`. A scanner finding attaches to a package through the existing `CARRIES_COMPLIANCE_FINDING` edge, whose source side is open.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-package-1 | Keyed By Ecosystem, Name And Version | Implemented | `computing_core__package` declares `NATURAL_KEY = (ecosystem, name, version)` and all three are required. The same name in another ecosystem, or another version, is another node. | `tests/test_software_inventory.py::TestPackage::test_found_again_by_ecosystem_name_and_version` |
| req-computing-core-package-2 | Architecture And Source Are Not Identity | Implemented | Changing `architecture` or `source_document` leaves the row findable by its key. | `::TestPackage::test_architecture_and_source_document_are_not_identity` |
| req-computing-core-package-3 | Ecosystem Is A Purl Type | Implemented | `ecosystem` is a lower-case purl type; an upper-case or empty value is refused. | `::TestPackage::test_ecosystem_is_a_purl_type` |
| req-computing-core-package-4 | Runtime Dimension | Implemented | A package carries `tap.computing: runtime`. | `::TestPackage::test_create_and_display` |
| req-computing-core-package-5 | Findings Attach Without A New Edge | Implemented | A `compliance_core` finding attaches to a package or a library with `CARRIES_COMPLIANCE_FINDING`; this plugin adds no finding edge. | `::TestEdges::test_a_scanner_finding_attaches_to_a_package_or_a_library` runs only on a grid with compliance_core installed. |

#### Why the purl, CPE and candidates are stored whole (2026-10-15)

A scanner matches on exactly what a document carries, so a thinner row finds less. Measured 2026-10-15 with Grype v0.120.1 on the tap-web SBOM of image `sha256:a9149a88…` (192 components; the full document gives 91 matches over 27 vulnerability ids), rebuilding the document from only the fields named:

| fields given to the scanner | matches | lost |
| --- | --- | --- |
| name, version, purl with `upstream=`, `cpe`, `syft:cpe23` candidates, distro | 91 | none |
| the same without the candidates | 89 | 2 (`python-3.14`) |
| the same without `cpe` | 50 | 41 (the self-built `openssl-fips-provider` matches by CPE alone) |
| purl with the `upstream=` qualifier removed, no `cpe` | 12 | 79 (`libssl3`, `libcrypto3`, glibc and python drop out, because Wolfi advisories are filed against the origin package) |

The distro resolved from the purl `distro=` qualifier even with no operating-system component, so the operating system is stored for the graph, not for the scan.

#### Acceptance Criteria (package, continued)

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-package-6 | Whole Purl Kept | Implemented | The `purl` column holds the purl exactly as the document gave it, `arch`, `distro` and `upstream` qualifiers included. The parser does not trim, normalise or rebuild it. | `tests/test_sbom_parse.py::TestMatchingFieldsSurvive::test_purl_qualifiers_survive`, `tests/test_software_inventory.py::TestPackage::test_whole_purl_is_stored_as_given`. The 1024-character column already holds them; the gap found 2026-10-15 was a bundle that wrote bare purls (177 of 178 rows). |
| req-computing-core-package-7 | CPE Candidates Are A Schema'd List | Implemented | `cpe_candidates` accepts a list of unique strings each beginning `cpe:2.3:` and refuses anything else; it defaults to the empty list and never repeats `cpe`. Declared in both `FIELD_CRUD_SCHEMA` and `FIELD_VALIDATION_SCHEMA` (a JSON column with no schema is `{type: object}` and blocks strict validation). | `tests/test_software_inventory.py::TestPackage::test_cpe_candidates_default_to_the_empty_list`, `::test_cpe_candidates_hold_a_list_of_cpe23_names`, `::test_cpe_candidates_refuse_anything_else`, `::test_cpe_candidates_never_repeat_cpe`, `::test_cpe_candidates_are_declared_in_both_schemas`. Additive migration `0011`. |
| req-computing-core-package-8 | One Observation, Never A Join | Implemented | `architecture` holds the one value the document gave for this component (the `arch=` qualifier). No writer concatenates two architectures into one string. | `tests/test_sbom_parse.py::TestOneArchitectureNeverAJoin`, `tests/test_software_inventory.py::TestPackage::test_architecture_is_one_value_never_a_join`. Found 2026-10-15: the inventory bundle held `aarch64, x86_64` in one column. The release is one node across architectures (above), so the column is the last observation, not a set. |

### Source Package Modeling
----
RID: `req-computing-core-source-package`

Status: `Implemented`

A `source_package` is the upstream source a package manager builds one or more binary packages from: an apk origin such as `glibc-2.44` or `python-3.14`, a deb `Source:`, an rpm source RPM. A vulnerability scanner reports against the binary `package`, but the thing to fix is the source: Trivy reports the same glibc CVEs against five installed apks and the same Python CVE against four, which a per-component count reads as five or four components (computing-core#38). George chose a node and an edge over a field on `package`, so counts and joins stay in Gryphon, whose aggregate needs an edge in the `MATCH`.

#### Implementation

| field | meaning |
| --- | --- |
| `ecosystem` | The package-URL type of the manager that builds it: `apk`, `deb`, `rpm`. Lower-case, an open vocabulary, as for `package`. Identity. |
| `name`, `version` | As the package manager reports them: the apk `o:` origin name, and the version of the binary package that names it. Members of one origin do not always share a version (see Observed), so one origin name can be more than one node. Identity. |

The node holds the key and nothing else. `purl`, `cpe`, `license` and `architecture` are facts about an installed binary and stay on the `package`; a source supplies a field of its own only when a source of data does, and none does yet.

**Observed (read 2026-10-15 from the apk database of the tap-web image).** All 101 records carry an `o:` line; they come from 69 source packages, 11 of which build more than one binary package. 47 of the 101 packages are their own origin. That older image's members of an origin shared one version; the SBOM of a later tap-web image does not hold to it (read 2026-10-15): of its 70 origin names, `openssl` is 3.6.4-r8 for `libssl3` and `libcrypto3` and 3.6.5-r2 for `openssl` and `openssl-dev`, and `postgresql-18` is 18.6-r5 for five members and 18.6-r4 for four, so the 70 names are 72 `(ecosystem, name, version)` source packages. Anything that joins a scanner finding to a source package must therefore go by the origin NAME, which is what Grype files `libssl3` findings against, and not by the one node a package happens to point at. The 14 package names in the Trivy alerts collapse to 6 sources (`glibc-2.44`, `python-3.14`, `openssl`, `busybox`, `py3-pip`, `zlib`).

**Every package draws the edge, including one that is its own source.** `DERIVES_FROM_SOURCE_PACKAGE` runs `package` to `source_package` even where the origin is the package itself, so a join by source never needs a fallback branch. Ecosystems with no binary/source split (pypi, npm) have no such edge. Nothing in this plugin emits these types yet; a collector or bundle does.

**A source package is not a package.** The two are different nodes of different types even when name and version coincide, because one is what is built and the other is what is installed; a finding attaches to the package (`CARRIES_COMPLIANCE_FINDING`) and is counted by following the edge to the source.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-source-package-1 | Keyed By Ecosystem, Name And Version | Implemented | `computing_core__source_package` declares `NATURAL_KEY = (ecosystem, name, version)` and all three are required. The same name in another ecosystem, or another version, is another node. | `tests/test_software_inventory.py::TestSourcePackage::test_found_again_by_ecosystem_name_and_version`, `::test_key_fields_required` |
| req-computing-core-source-package-2 | Ecosystem Is A Purl Type | Implemented | `ecosystem` is a lower-case purl type; an upper-case or empty value is refused. | `::TestSourcePackage::test_ecosystem_is_a_purl_type` |
| req-computing-core-source-package-3 | Key Only, Runtime Dimension | Implemented | The node has no `purl`, `cpe`, `license`, `architecture` or `source_document` column, and carries `tap.computing: runtime`. | `::TestSourcePackage::test_it_holds_the_key_and_nothing_else`, `::test_create_and_display` |
| req-computing-core-source-package-4 | Many Packages, One Source; Self-Origin Still Drawn | Implemented | Several packages draw the edge to one source package, a package that is its own origin is still two nodes joined by the edge. | `::TestSourcePackage::test_a_package_and_its_source_package_are_two_nodes`, `::TestEdges::test_one_source_package_has_many_packages_and_a_self_origin_still_gets_the_edge` |

### Library Modeling
----
RID: `req-computing-core-library`

Status: `Implemented`

A `library` is a programmatic library an application imports or links that was built or vendored outside a package manager: the OpenSSL FIPS provider compiled from a pinned tarball, the `cryptography` distribution compiled from its sdist (computing-core#33). These are the components an SBOM knows only because someone declared them (tap `req-cicd-sbom-3`), and the ones a vulnerability has to be attributed to by hand.

#### Implementation

| field | meaning |
| --- | --- |
| `ecosystem`, `name`, `version` | As for `package`. `generic` for a tarball with no registry. Identity. |
| `language` | Implementation language: `c`, `python`, `rust`, `go`. |
| `purl`, `cpe`, `license` | As for `package`. For a `pkg:generic` library the CPE is what lets an advisory feed match at all (tap `docker/sbom-supplemental.json`). |
| `source_kind` | `self-built`, `source-built` or `copied-image`: how it entered the artifact without a package manager installing it. The first and last are the supplemental manifest's `source_kind`; `source-built` is a registry package compiled from its sdist (tap `req-cicd-sbom-12-6`). `null` means not observed. |
| `source_url` | Where the source it was built from was fetched. |
| `path` | Where it sits in the artifact. |

**Cryptography is an edge.** Whether a library carries cryptography is the presence of `CARRIES_CRYPTO_PROVIDER` to a `crypto_provider`, which also says which provider and its disposition. There is no `carries_cryptography` column: it would be a second writable copy of that edge. A library that carries cryptography nobody has classified yet has an edge to a `crypto_provider` whose `boundary` is `null`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-library-1 | Keyed By Ecosystem, Name And Version | Implemented | `computing_core__library` declares `NATURAL_KEY = (ecosystem, name, version)`; all three are required. | `tests/test_software_inventory.py::TestLibrary::test_key_fields_required` |
| req-computing-core-library-2 | Distinct From Package | Implemented | A package and a library of one name and version are two nodes of two types; neither is a subtype of the other. | `::TestLibrary::test_a_package_and_a_library_of_one_name_are_two_nodes` |
| req-computing-core-library-3 | Source Kind Is Closed, Null Is Unobserved | Implemented | `source_kind` accepts only the three values or `null`. | Authorizes the model's `# noqa: DJ001  (req-computing-core-library-3)`. `::TestLibrary::test_source_kind_is_a_closed_vocabulary_and_null_is_unobserved` |
| req-computing-core-library-4 | Cryptography Is Not A Column | Implemented | The model has no field recording that it carries cryptography; the `CARRIES_CRYPTO_PROVIDER` edge is that fact. | `::TestLibrary::test_cryptography_is_an_edge_not_a_column` |

### Operating System Modeling
----
RID: `req-computing-core-operating-system`

Status: `Implemented`

An `operating_system` is an OS as a distro publishes it: Wolfi, Ubuntu 24.04, Windows Server 2022. It is the `operating_system` row of the model catalog (`req-computing-core-models`), built. A `host` runs one with `RUNS_OPERATING_SYSTEM`.

#### Implementation

| field | meaning |
| --- | --- |
| `os_id` | `/etc/os-release` `ID`: `wolfi`, `ubuntu`, `debian`. Identity; must not be empty. |
| `version_id` | `VERSION_ID` exactly as reported, even when it is a placeholder (Wolfi reports `20230201` on every build). Empty when the OS reports none. Identity. |
| `build_id` | `BUILD_ID` where the distro sets one; for a rolling distro, what pins the build (for a container, the digest of the pinned base image). Empty means none and not rolling. Identity. |
| `name` | Display name (`NAME`). |
| `vendor` | Who publishes it. |
| `rolling` | `true` for a rolling-release distro, whose `version_id` does not identify a build. `null` means not observed. |
| `base_image` | The image reference, with digest, this OS came from, when it came from one. |
| `end_of_life` | An ISO date. `null` means none published or not observed. |

**Why three parts.** Wolfi is a rolling distribution: `ID=wolfi` and a fixed placeholder `VERSION_ID` on every build. Keyed on those two alone, every Wolfi image ever built would be one node, and a vulnerability fixed in the 2026-10 base would read as present in the 2026-05 one. The real identity is the pinned base-image digest together with the installed package set; the digest goes in `build_id`, and the package set is the `package` nodes the hosts running that image install. All three key parts must be present in a write: a collector that forgot `build_id` would otherwise mint a node indistinguishable from an OS that reports none.

**`host.os` is not migrated.** `host.os` remains the free-text report of the same fact (`req-computing-core-host` says it "can become its own `operating_system` node later without migrating this field"). Nothing derives one from the other.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-operating-system-1 | Keyed By Id, Version And Build | Implemented | `computing_core__operating_system` declares `NATURAL_KEY = (os_id, version_id, build_id)`. A rename of `name` leaves the row findable. | `tests/test_software_inventory.py::TestOperatingSystem::test_found_again_across_a_rename_of_the_display_name` |
| req-computing-core-operating-system-2 | A Placeholder Version Does Not Merge Builds | Implemented | Two operating systems with one `os_id` and `version_id` and different `build_id` are two nodes. | `::TestOperatingSystem::test_a_placeholder_version_id_does_not_merge_two_builds` |
| req-computing-core-operating-system-3 | Every Key Part Is Present | Implemented | A write missing `os_id`, `version_id` or `build_id` is refused; `version_id` and `build_id` may be empty strings, `os_id` may not. | `::TestOperatingSystem::test_every_key_part_must_be_present`, `::test_os_id_must_not_be_empty_but_the_others_may_be` |
| req-computing-core-operating-system-4 | Null Is Unobserved | Implemented | `rolling` and `end_of_life` default to `null`; `end_of_life` accepts only an ISO date. | `::TestOperatingSystem::test_rolling_and_end_of_life_default_to_unobserved`, `::test_end_of_life_is_an_iso_date` |
| req-computing-core-operating-system-5 | Host OS Stays Free Text | Implemented | `host.os` is unchanged and still accepts a free-text report. | `::TestOperatingSystem::test_host_os_stays_the_free_text_report` |

### Crypto Provider Modeling
----
RID: `req-computing-core-crypto-provider`

Status: `Implemented`

A `crypto_provider` is a cryptographic implementation found in an artifact, and what was decided about it. It is the finding tap's crypto-BOM gate produces (`req-fips-crypto-bom`) put on the grid: the OpenSSL FIPS provider, a Go binary's `crypto/tls`, a Rust crate's `aws-lc-rs`, a `libsodium` wheel. FIPS is not "everything uses OpenSSL"; it is that every provider that can execute is the validated module, an equivalent, proven unreached, or named out of boundary. This node is where that disposition is readable without running the scanner.

#### Implementation

| field | meaning |
| --- | --- |
| `scope` | What was scanned: the image or environment the finding is from (`tap-web`), or a plugin slug. Identity. |
| `artifact` | Where it was found: an absolute path (`/usr/lib/ossl-modules/fips.so`), or `dist:<name>` for an installed distribution. Identity. |
| `provider` | The implementation, by the registry's name: `openssl-system`, `openssl-fips-provider`, `go-crypto`, `rust-aws-lc-rs`, `libsodium`. Identity. |
| `provider_kind` | `fips-module` (the validated module itself), `system-openssl` (routes through it), `embedded-openssl`, `non-openssl`. Required. |
| `boundary` | The disposition, spelled as tap's `Boundary`: `validated`, `fips-mode-unvalidated-build`, `out-of-boundary`, `unreached`, `must-fix`. `null` means detected and not dispositioned, which the gate fails closed on. |
| `rationale` | Why that boundary: the registry's reviewed sentence. |
| `fips_validation` | The validation status of the module as shipped, as a sentence. |

**Presence, never material.** The node records that an implementation is present and what was decided. It has no field that could hold key material, a fingerprint or file contents, and a test fails if one is added. The CycloneDX CBOM `cryptographic-asset` models algorithms, protocols, certificates and key material and has no implementation-level disposition, so none of its fields are borrowed.

**`validated` is not a claim made here.** A provider whose `boundary` is `fips-mode-unvalidated-build` runs in FIPS mode but is not CMVP-validated as shipped; the distinct value exists so presence cannot be read as a certificate. This plugin stores the disposition a collector reports and verifies nothing.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-crypto-provider-1 | Keyed By Scope, Artifact And Provider | Implemented | `computing_core__crypto_provider` declares `NATURAL_KEY = (scope, artifact, provider)`; a change of `boundary` leaves the row findable, and the same finding in another scope is another node. | `tests/test_software_inventory.py::TestCryptoProvider::test_found_again_by_scope_artifact_and_provider` |
| req-computing-core-crypto-provider-2 | Boundary Vocabulary Matches The Registry | Implemented | `boundary` accepts exactly the five values of tap's `Boundary`, and nothing else. | `::TestCryptoProvider::test_every_registry_boundary_is_accepted`, `::test_boundary_is_closed_and_null_is_unclassified` |
| req-computing-core-crypto-provider-3 | Null Is Unclassified | Implemented | A provider written without `boundary` is stored with `null`, not refused and not defaulted to a safe-looking value. | Authorizes the model's `# noqa: DJ001  (req-computing-core-crypto-provider-3)`. `::TestCryptoProvider::test_boundary_is_closed_and_null_is_unclassified` |
| req-computing-core-crypto-provider-4 | Kind Is Required And Closed | Implemented | `provider_kind` is required and accepts only the four values. | `::TestCryptoProvider::test_required_fields`, `::test_provider_kind_is_closed` |
| req-computing-core-crypto-provider-5 | No Field Can Hold Key Material | Implemented | The model has no column named for a key, fingerprint, secret, content or hash. | `::TestCryptoProvider::test_it_has_no_field_that_could_hold_key_material` |

### Software Inventory Edges
----
RID: `req-computing-core-inventory-edges`

Status: `Implemented`

Six edges connect the inventory types to `host`, `program` and each other. Each is a reference, not containment: a package, library, operating system or provider outlives and is shared by the things pointing at it, so none is in any model's `CONTAINMENT_EDGES`, and retiring a host leaves them. None carries properties; each declares the plain identity (`discriminators: []`). All carry `tap.computing: runtime`.

#### Implementation

| edge | sentence | justification |
| --- | --- | --- |
| `INSTALLS_PACKAGE__computing_core` | `<host> INSTALLS_PACKAGE <package>` | the packages table of an image or host |
| `DERIVES_FROM_SOURCE_PACKAGE__computing_core` | `<package> DERIVES_FROM_SOURCE_PACKAGE <source_package>` | the source a binary package is built from (computing-core#38): the apk `o:` origin, a deb `Source:`, an rpm source RPM. Drawn for every package, including one that is its own source. `DERIVES_FROM` alone would end in a preposition (`req-tap-plugin-edge-naming`), so the object noun is part of the slug |
| `SHIPS_LIBRARY__computing_core` | `<package> SHIPS_LIBRARY <library>` | a library a package bundles (computing-core#33); a library built outside a package manager has none |
| `LOADS_LIBRARY__computing_core` | `<program> LOADS_LIBRARY <library>` | which software runs a library. `LINKS_LIBRARY` (the issue's proposal) is not true of a Python import, and the question is the same |
| `RUNS_OPERATING_SYSTEM__computing_core` | `<host> RUNS_OPERATING_SYSTEM <operating_system>` | the operating-systems table. `RUNS_ON` would end in a preposition (`req-tap-plugin-edge-naming`) |
| `CARRIES_CRYPTO_PROVIDER__computing_core` | `<library \| package \| program> CARRIES_CRYPTO_PROVIDER <crypto_provider>` | the crypto-providers table's "carried by" column. One relationship, three kinds of code: the library is the provider, or embeds it, or routes its cryptography through it |

There is no operating-system-to-package edge: which packages an OS comprises is the packages its hosts install, and a second statement of that would be two copies. There is no container-image type here; a container is a `host` with `kind: container`.

### Runtime Edges
----
RID: `req-computing-core-runtime-edges`

Status: `Implemented`

Two edges say what a node runs. Both are references, not containment (no model lists either in `CONTAINMENT_EDGES`, no cascade follows them), declare the plain identity and no properties, and carry `tap.computing: runtime`. Both have an open source, because what runs a program or an image is not enumerable and the first source of `RUNS_IMAGE` is an `aws_core` container, which this plugin must not name.

#### Implementation

| edge | sentence | justification |
| --- | --- | --- |
| `RUNS_PROGRAM__computing_core` | `<any node> RUNS_PROGRAM <program>` | one verb for both uses: a container runs gunicorn, and gunicorn runs tap-web. Target `computing_core__program` |
| `RUNS_IMAGE__computing_core` | `<any node> RUNS_IMAGE <host>` | a container runs the image it was started from. The target is a `computing_core__host` of kind container, the image host (see above: there is no image type). Target `computing_core__host` |

The verb is `RUNS_*`, as in `RUNS_OPERATING_SYSTEM` here and `RUNS_SERVICE`, `RUNS_TASK` and `RUNS_CONTAINER` in `aws_core`, so a path from a service down to a program reads in one verb. It stands in for the candidate `EXECUTES` in the table under [Edge Types](#edge-types).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-runtime-edges-1 | Program And Image Sentences Connect | Implemented | `RUNS_PROGRAM` connects any node to a `program` and `RUNS_IMAGE` any node to a `host`, each carrying `tap.computing: runtime`; a program may run a program, so a container-to-gunicorn and a gunicorn-to-tap-web edge are the same type. | `tests/test_application_flow.py::TestEdges::test_runs_program_and_runs_image_connect` |
| req-computing-core-runtime-edges-2 | Target Type Is Enforced Where Declared | Implemented | `RUNS_PROGRAM` to a `host` is refused. The edge definition's `targets` is a grant, not a restriction, so a target type that declares no edges (`program`, `tcp_connection`) stays open at its end, exactly as in `req-computing-core-inventory-edges-2`. | `::TestEdges::test_runs_program_to_a_host_is_refused` |
| req-computing-core-runtime-edges-3 | References, Open Source, Plain Identity | Implemented | Both edges omit `sources`, declare the plain identity and no properties, carry `tap.computing: runtime`, and retiring the source with `cascade="contained"` leaves the target. | `::TestEdges::test_runs_edges_are_open_at_the_source_plain_and_not_containment` |
| req-computing-core-runtime-edges-4 | An Operating System Holds Its Programs | Implemented | `RUNS_PROGRAM` from an `operating_system` to a `program` connects: the operating system holds the programs that are part of it (an init system, an SSH daemon, a shell) and every host running that operating system inherits them. No new edge is drawn for this; the semantics are recorded here so a reader does not take the edge to mean "this host is executing the program". If the grid refuses the edge because `operating_system` declares edges (`INBOUND_EDGES` only), the change is one `OUTBOUND_EDGES` entry on `operating_system` in this release, tested before any data depends on it. | George ruled 2026-10-20, relayed by rampart-pg, that this use of `RUNS_PROGRAM` stands in for a missing official edge. Whether the grid accepts it was read (`operating_system.py` declares inbound only), not run. |

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-inventory-edges-1 | The Sentences Connect | Implemented | Each edge connects its declared source type to its declared target type and carries `tap.computing: runtime`. | `tests/test_software_inventory.py::TestEdges::test_the_sentences_connect` |
| req-computing-core-inventory-edges-2 | Wrong Direction Or Type Is Refused | Implemented | The reverse of each edge, and an edge of the wrong endpoint type, are refused wherever an endpoint type declares its edges (`host`, `package`, `source_package`, `library`, `operating_system`, `crypto_provider`). | `::TestEdges::test_the_wrong_way_round_or_wrong_type_is_refused`. The grid permits an edge when either the node's declaration or the edge definition allows each side, so `program`, which declares no edges, leaves its side open; the edge definition's `sources` is then a grant, not a restriction. |
| req-computing-core-inventory-edges-3 | References, Not Containment | Implemented | Retiring a host with `cascade="contained"` leaves the package, source package, operating system, library and provider reachable from it. | `::TestEdges::test_none_of_them_is_containment` |
| req-computing-core-inventory-edges-4 | Plain Identity, No Properties | Implemented | Each edge declares `identity: {discriminators: []}` (found again by type, source and target), has no `property_schema`, and carries `tap.computing: runtime`. | `::TestEdges::test_every_edge_declares_the_plain_identity_and_no_properties` |

### Package Dependencies
----
RID: `req-computing-core-package-dependency`

Status: `Implemented`

One edge records which package needs which, as an SBOM's `dependencies[].dependsOn` lists it. George ruled 2026-10-15 that the links become edges "for now": the tap-web SBOM carries 457 `dependsOn` entries over 129 components, and every one resolves to a listed component and to a package, none to itself (read 2026-10-15). The document lists seven npm packages twice or three times, once per path they were found at, and those are one node each, so the 457 entries are 450 distinct package pairs (read 2026-10-15).

#### Implementation

| edge | sentence | justification |
| --- | --- | --- |
| `REQUIRES_PACKAGE__computing_core` | `<package> REQUIRES_PACKAGE <package>` | the document's dependency graph. `DEPENDS_ON` would end in a preposition (`req-tap-plugin-edge-naming`), so the object noun is part of the slug |

A reference, not containment: a dependency outlives the package that named it, and none is in any model's `CONTAINMENT_EDGES`. The edge has no properties and declares the plain identity (`discriminators: []`); it carries `tap.computing: runtime`. A package is never drawn as requiring itself, and a `dependsOn` that names a library, a program or a component the document does not list is not drawn; the parser counts it in its report (`req-computing-core-sbom-parse-8`) instead of inventing an endpoint.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-package-dependency-1 | The Sentence Connects | Implemented | `REQUIRES_PACKAGE` connects a `package` to a `package`; the reverse and any other endpoint type are refused wherever an endpoint declares its edges. | `::TestEdges::test_the_sentences_connect`, `::test_the_wrong_way_round_or_wrong_type_is_refused` |
| req-computing-core-package-dependency-2 | Plain, Reference, Runtime | Implemented | The edge declares `identity: {discriminators: []}`, has no `property_schema`, carries `tap.computing: runtime`, and retiring a package leaves the packages it required reachable. | `::TestEdges::test_every_edge_declares_the_plain_identity_and_no_properties`, `::test_retiring_a_package_leaves_the_packages_it_required`, `::test_none_of_them_is_containment` |
| req-computing-core-package-dependency-3 | No Self-Edge | Implemented | A document listing a component as depending on itself yields no edge. | `tests/test_sbom_parse.py::TestSkipsAreCounted::test_a_component_depending_on_itself_yields_no_edge`, `::test_two_listings_of_one_package_are_one_node_so_a_link_between_them_is_a_self_edge`. |

### Program Root Package
----
RID: `req-computing-core-program-package`

Status: `Implemented`

An SBOM lists what an image holds and which package needs which (`REQUIRES_PACKAGE`). It does not say which program the image exists to run, so the grid can follow a package to the hosts that install it but not to the program that uses it. One edge closes the gap for the packages a program is built from: it names the program's **root package**, the package whose code is the program itself. The packages the program consumes are then everything reachable from the root along `REQUIRES_PACKAGE`. Read 2026-10-20 in the corpus document `tap-web-latest-arm64.cdx.json`: `tap` is a graph root (no component depends on it) and its closure along `dependsOn` is 43 pypi packages, so one edge to `tap` reaches the application's whole Python closure. The same document has no edge from a pypi component to an apk component (0 of 457), so a program's closure never includes system packages; those stay with the host that installs them, and a consumer that needs a rule for them applies its own (for example, the container's programs).

#### Implementation

| edge | sentence | justification |
| --- | --- | --- |
| `RUNS_PACKAGE__computing_core` | `<program> RUNS_PACKAGE <package>` | the package this program is. `RUNS_*` is the verb the neighbouring edges use (`RUNS_PROGRAM`, `RUNS_IMAGE`, `RUNS_OPERATING_SYSTEM`); the slug has two tokens, no modal and no trailing preposition (`req-tap-plugin-edge-naming`) |

The edge is a reference, not containment: a package outlives the program that names it, and the edge is in no model's `CONTAINMENT_EDGES`. It declares the plain identity (`discriminators: []`), has no `property_schema`, and carries `tap.computing: runtime`. Its source is `computing_core__program` and its target is `computing_core__package`. `program` declares no edges, so its side stays open; `package` already declares edges, so its `INBOUND_EDGES` gains the slug.

The edge states a root, not a closure. No edge is drawn from a program to a package it merely reaches through `REQUIRES_PACKAGE`, because that would be a second copy of the dependency graph. A program may have more than one root (a Python application and the interpreter package that runs it, say), and a package may be the root of more than one program.

Who draws it. The SBOM does not say which package is the program, so the parser (`req-computing-core-sbom-parse`) draws no `RUNS_PACKAGE` edge. Whoever knows the pairing draws it: a seed, a collector, or a person. Declaring the roots in the build, so that the generator states them in the signed document and the parser draws the edge, is the Backlog requirement `req-computing-core-program-package-declared`; it needs the parser to find the `program` node from the document, which this requirement does not settle.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-program-package-1 | The Sentence Connects | Implemented | `RUNS_PACKAGE` connects a `program` to a `package` and carries `tap.computing: runtime`; the reverse and any other target type are refused wherever an endpoint declares its edges. | As `req-computing-core-inventory-edges-2`: `program` declares no edges, so its side is a grant, not a restriction. |
| req-computing-core-program-package-2 | Plain, Reference, Runtime | Implemented | The edge declares `identity: {discriminators: []}`, has no `property_schema`, is in no model's `CONTAINMENT_EDGES`, and retiring a program leaves its root package reachable. | As `req-computing-core-package-dependency-2`. |
| req-computing-core-program-package-3 | A Root Is Not A Closure | Implemented | The plugin ships no edge, collector or parser output that draws `RUNS_PACKAGE` to a package only reachable through `REQUIRES_PACKAGE`. | A review item: the closure is a walk over the existing edge. |
| req-computing-core-program-package-4 | More Than One Root, And Shared Roots | Implemented | One program may draw the edge to several packages and one package may be the target of several programs; each pair is one edge. | Found again by type, source and target (the plain identity). |
| req-computing-core-program-package-5 | Registered In The Manifest | Implemented | The manifest registers the edge, its slug equals its file name, and `package` lists the slug in its `INBOUND_EDGES`. | |
| req-computing-core-program-package-6 | The Parser Draws None | Implemented | Parsing a document yields no `RUNS_PACKAGE` edge, and the parse report says nothing about one. | Until `req-computing-core-program-package-declared` lands. |

### Program Key Use
----
RID: `req-computing-core-program-key`

Status: `Implemented`

A program can read a key or a file that is not part of any package: a server's TLS private key and certificate, a signing key. No edge says so today. `GENERATES_FILE` says a file was produced by something, not that a program uses it, and `RUNS_PROGRAM` can only target a program. One edge says the program uses the key or file. George ruled 2026-10-20, relayed by rampart-pg, to add the edge and cut a release with `RUNS_PACKAGE` in the same release, after the Overview page's container interior needed to show gunicorn using the container's TLS key pair.

#### Implementation

| edge | sentence | justification |
| --- | --- | --- |
| `USES_KEY__computing_core` | `<program> USES_KEY <private_key \| public_key \| file>` | the program reads this key material or this file at run time. The slug is George's and rampart-pg's wording; its target also admits a `file` (a certificate or key held as a file), which the builder may reword if `req-tap-plugin-edge-naming` or review prefers; two tokens, no modal, no trailing preposition |

The edge is a reference, not containment: a key outlives the program that reads it, and the edge is in no model's `CONTAINMENT_EDGES`. It declares the plain identity (`discriminators: []`), has no `property_schema`, and carries `tap.computing: runtime`. Its source is `computing_core__program`; its targets are `computing_core__private_key`, `computing_core__public_key` and `computing_core__file`. `program`, `private_key`, `public_key` and `file` declare no edges (read 2026-10-20), so both ends are open and no model gains an `INBOUND_EDGES` or `OUTBOUND_EDGES` entry. The edge carries no key material and adds no field to any of the three target models.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-program-key-1 | The Sentence Connects | Implemented | `USES_KEY` connects a `program` to a `private_key`, a `public_key` or a `file` and carries `tap.computing: runtime`; the reverse is refused wherever an endpoint declares its edges. | As `req-computing-core-inventory-edges-2`: none of the four types declares edges, so the ends are grants, not restrictions. |
| req-computing-core-program-key-2 | Plain, Reference, Runtime | Implemented | The edge declares `identity: {discriminators: []}`, has no `property_schema`, is in no model's `CONTAINMENT_EDGES`, and retiring a program leaves the key or file reachable. | As `req-computing-core-package-dependency-2`. |
| req-computing-core-program-key-3 | Registered In The Manifest | Implemented | The manifest registers the edge and its slug equals its file name. | |
| req-computing-core-program-key-4 | One Release | Implemented | `RUNS_PACKAGE`, `USES_KEY` and the operating-system acceptance in `req-computing-core-runtime-edges-4` ship in one computing_core release. | George ruled 2026-10-20. |

### SBOM Document
----
RID: `req-computing-core-sbom-document`

Status: `Implemented`

An `sbom_document` is the record that one SBOM existed: which bytes (by digest), which revision of which lineage, what it described, and who signed it. It is not the SBOM. The grid does not hold the document body; storing and serving the file is tap#1035, and until that lands the digest is how a copy held elsewhere is checked against the grid's record. George ruled the SBOM is not stored in the database (2026-10-15).

#### Implementation

| field | meaning |
| --- | --- |
| `content_digest` | SHA-256 of the document's exact bytes, lower-case hex. Identity, and the idempotency key: the same bytes are the same node. |
| `format`, `spec_version` | `cyclonedx` and the document's `specVersion` (`1.7`). SPDX is not read yet (`req-computing-core-sbom-parse-7`). |
| `serial_number` | The document's `serialNumber` (`urn:uuid:…`). With `subject_digest`, names the lineage. |
| `revision` | The document's `version`, an integer from 1. A rescan of one image is the next revision of the same lineage, so a later scan is a higher number, not a new unrelated document. |
| `subject_digest` | The digest of the artifact described (an image digest `sha256:…`), from the attestation subject or the document's own `metadata.component`; empty where neither names one. The parser takes the document's bytes only, so it reads `metadata.component` (the document's own `version` when that is a digest); an attestation subject is a caller's to supply. |
| `produced_at`, `generator` | `metadata.timestamp`, and the first tool as `name@version` (`syft@1.51.0`). |
| `component_count` | How many components the document lists. |
| `signer`, `verified`, `verification_note` | The identity of the verified signer, and whether verification ran. A check or a signer carries no control character or newline, and every pattern ends at the end of the string (a trailing newline is refused). The tri-state maps the ingest outcome of `req-cicd-sbom-22-9` one to one: `verified` is `true`, `refused` is `false`, `not-observable` is `null`. `signer` is non-empty exactly when `verified` is `true` (a verified document names its signer). `verification_note` (up to 255 characters) is the one place a non-verified outcome says why: for a refused document it names the failing check (`signer-identity`, `subject-digest` or `predicate-type`) and is required; for a `null` it may give the reason; for a verified one it is empty. Verification happens in the caller against the signer trust list; this node records its outcome and does not decide it. A document that is not `verified` is recorded and never parsed (`req-computing-core-sbom-parse-10`). |

**Bounded values.** Every field is bounded to its column: `generator` 255, `spec_version` 16, `signer` 512, `subject_digest` `<algorithm>:<hex>` up to 160, `revision` and `component_count` up to 2147483647, and `produced_at` an RFC 3339 date-time with a zone (`20261015` is refused, because a column would parse it and a reader would misread it). A caller that has a value outside these leaves the field empty and says why; the node refuses it otherwise.

**Lineage and "current".** Documents sharing `(subject_digest, serial_number)` are one lineage; the current one is the highest `revision` among the documents with `verified` true. A refused or unchecked document (`verified` false or null) is kept but is never current and never supersedes a verified one, whatever its revision; a lineage with no verified document has no current one. All earlier revisions are kept (ruled 2026-10-15: the files are not in the database, so a retained row costs one node). Two different byte strings that claim the same `(serial_number, revision)` are two nodes, because their digests differ; the grid records the clash and does not pick between them.

**No membership edges.** A document does not draw an edge to each package it lists: that is about 190 edges per revision, repeated every night for no new fact. What a host installs is its `INSTALLS_PACKAGE` edges, and `source_document` on the package names the kind of document that last observed it. The cost is that "exactly what revision N listed" is answered from the file, not the grid.

**One edge.** `DESCRIBES_HOST__computing_core`: `<sbom_document> DESCRIBES_HOST <host>`, the host (a container image's `host` with `kind: container`) the document inventories. A reference, no properties, plain identity, `tap.computing: runtime`, not containment.

Dimension `tap.computing: runtime`. Natural key `(content_digest)`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-sbom-document-1 | Keyed By Content Digest | Implemented | `computing_core__sbom_document` declares `NATURAL_KEY = (content_digest)`; the digest is required and must be 64 lower-case hex characters. | `tests/test_sbom_document.py::TestKeyedByContentDigest` |
| req-computing-core-sbom-document-2 | Same Bytes, One Node; Revisions Accumulate | Implemented | Ingesting the same bytes twice leaves one node. Ingesting a higher `revision` of the same lineage adds a node and leaves the earlier one. | `tests/test_sbom_document.py::TestRevisionsAccumulate` |
| req-computing-core-sbom-document-3 | Verified Is Three-State | Implemented | `verified` accepts `true`, `false` or `null` (not checked); `signer` is refused non-empty unless `verified` is `true`, and refused empty when it is. | `tests/test_sbom_document.py::TestVerifiedIsThreeState`, `::TestStrictShapes` |
| req-computing-core-sbom-document-4 | Describes A Host | Implemented | `DESCRIBES_HOST` connects an `sbom_document` to a `host`; the reverse and other endpoint types are refused; it declares the plain identity and no properties. | `tests/test_sbom_document.py::TestDescribesHost`; the edge also in `tests/test_software_inventory.py::TestEdges` |
| req-computing-core-sbom-document-5 | No Document Body | Implemented | No column holds the document or its components, and a create carrying one is refused. | `tests/test_sbom_document.py::TestNoDocumentBody`. Sits beside `req-computing-core-models-7`. |
| req-computing-core-sbom-document-6 | Refusal Names Its Check | Implemented | A refused document (`verified` false) requires a non-empty `verification_note` (at most 255 characters); a verified one refuses a note; a `null` may carry one. | `tests/test_sbom_document.py::TestARefusedDocumentNamesItsCheck`. Feeds `req-cicd-sbom-22-9`: the failing check is named on the node, never dropped. |
| req-computing-core-sbom-document-7 | Current Is Verified Only | Implemented | `SbomDocument.current(subject_digest, serial_number)` returns the highest-`revision` document whose `verified` is `true`; a refused or unchecked document is never current. | `tests/test_sbom_document.py::TestCurrentIsVerifiedOnly`. |

### SBOM Parser
----
RID: `req-computing-core-sbom-parse`

Status: `Implemented`

`parse_cyclonedx(data: bytes, *, host_id) -> SbomBatch` turns one CycloneDX JSON document into the grid's inventory: packages, libraries, source packages, the operating system, the `sbom_document` record and the edges between them. George ruled 2026-10-15 that SBOMs become the source of truth for packages and that this parser lives in computing_core, so any collector, action or other pipeline can call it; the github_core collector is its first caller, finding and downloading the document and handing over the bytes.

#### Implementation

**Pure.** The module (`tap_plugin/computing_core/sbom/`) imports no Django, opens no socket or file and reads no clock. Its caller supplies the bytes and the `host_id` of the host the document describes (the caller resolves it, as github_core resolves its own endpoints). The batch carries no entity id. The grid does not derive ids from keys: `Entity.id` is always an assigned UUIDv7 and a row is found again by its natural key (`tap_grid/natural_key.py`), so no Django-free derivation exists to call and the parser invents none. Every node row names itself by a batch-local `ref` (the grid's `identity_lock_key` over the type and its natural-key values, a label that never becomes an id) and carries its properties; every edge row names its endpoints by `from_ref` / `to_ref`, and the host by the `host_id` the caller gave. The GRIFT importer resolves each ref against the grid's natural key (`req-grid-import-grift-identity-3`), so the same bytes give the same batch on any machine and the same document imported twice is a replace, not a duplicate.

**Untrusted input.** The document is data from outside. Size, nesting depth and component count are capped; a document over a cap is refused with the cap named, not truncated. The size cap is 8 MiB: the tap-web document is 0.6 MB, so the cap is 13 times a real one, and it is the bound on the parse itself, because `json.loads` builds the whole tree before anything can be counted (30 MB of `{},` took 6 s and 1.36 GB, measured 2026-10-15). A string that cannot be written as UTF-8 (a lone surrogate from a `\ud800` escape) refuses the document, as does a repeated JSON key, `NaN` and an integer literal past the interpreter's digit limit.

**Wrong shapes and over-long values.** A field of the wrong shape (a `properties`, `licenses`, `dependencies` or nested `components` that is not a list) is ignored and the report says so; a nested `components` that is not a list is counted with the skipped components. A value longer than its column (name 255, version 128, purl 1024, ecosystem 32, `cpe` and `license` 512, `architecture` 32, library `source_url` and `path` 1024, operating-system id and version 64, `generator` 255, `revision` 2147483647) never reaches a row: a key field over its limit skips the component with the reason counted, any other field is left empty with a note. `metadata.timestamp` must be an RFC 3339 date-time with a zone, and `subject_digest` an `<algorithm>:<hex>` of at most 160 characters. Qualifiers: the scheme `pkg:` is read in any case (the purl is stored as given), a qualifier key is lower-cased, a key that appears twice is ignored altogether, a value that is not valid percent-encoded UTF-8 is ignored, and an `upstream` or origin that is not a package name is never used as a source package's name.

**Mapping.** A component is classified by its purl type, not by CycloneDX's `type`, because Syft types `uv` as `application` and the self-built provider as `library`:

| in the document | on the grid |
| --- | --- |
| purl type `apk`, `deb`, `rpm`, `pypi`, `npm`, `golang`, `cargo`, `gem`, `maven`, `nuget` | `package`: `ecosystem` is the purl type, `name`, `version`, whole `purl`, `architecture` from `arch=`, `cpe`, `cpe_candidates` from the repeated `syft:cpe23` properties that differ from `cpe`, `license` as an SPDX expression, `source_document` `sbom` |
| purl type `generic` or `github`, or no purl on a CycloneDX `library`, `framework` or `application` | `library` (built or vendored outside a package manager). `ecosystem` is the purl type (`generic` with no purl). `source_kind`, `source_url` and `path` come from the document's `tap:source_kind`, `tap:source` and `tap:path` properties when it carries them (the tap-web document does, for all three libraries); `source_kind` is null where it does not say or says something outside the vocabulary |
| any other purl type, or no purl on any other CycloneDX type | no node; counted in the report with its reason (`req-computing-core-sbom-parse-8`) |
| `type: operating-system` | `operating_system`: `os_id` from `syft:distro:id`, `version_id` from `syft:distro:versionID`, `build_id` empty |
| `syft:metadata:originPackage` (all 102 apk components carry it; the purl `upstream=` qualifier appears on the 54 whose origin differs from their name) | `source_package` of the package's ecosystem, the origin's name (the property, else the purl `upstream=` qualifier, else the package's own name), and the package's own version; `DERIVES_FROM_SOURCE_PACKAGE` for every apk package, a package that is its own origin included. Members of one origin do not always share a version (read 2026-10-15 from the corpus: `openssl` is 3.6.4-r8 and 3.6.5-r2, `postgresql-18` is 18.6-r4 and 18.6-r5), so 70 origin names give 72 source packages |
| `dependencies[].dependsOn` | `REQUIRES_PACKAGE` (`req-computing-core-package-dependency`) |
| the whole document | `sbom_document` with `DESCRIBES_HOST` to `host_id`; the host also gets `INSTALLS_PACKAGE` to each package and `RUNS_OPERATING_SYSTEM` |

A library has no edge in the batch: the vocabulary has no host-to-library edge (`SHIPS_LIBRARY` runs from a package, `LOADS_LIBRARY` from a program, and the document names neither relation), so a library node is reachable only by its own key until a collector or a later edge says what ships or loads it. CycloneDX `bom-ref` is a handle inside one document and is used only to resolve `dependencies`; it is not stored. File hashes are not stored (3 of 192 components carry one in the tap-web document).

**Duplicates.** A component listed twice with one `(ecosystem, name, version)` is one node. If the copies carry different purls, the lexicographically smallest is kept and the report names the others, so the result does not depend on document order. The key is `(ecosystem, name, version)` and nothing else, so a purl namespace and an architecture are not identity: `maven` `org.a:core@1` and `org.b:core@1` are one package, and a deb `curl@8` for `amd64` and for `arm64` is one package (the smallest purl is kept, `architecture` is that purl's, and the report's `purl_conflicts` names both). Keeping them apart would need the namespace or architecture in the natural key, which is a model change this spec does not make.

**Fail closed.** A document the parser cannot read raises `SbomParseError` naming why. It never returns an empty batch, because an empty batch reads as "this host has no software".

**The corpus.** The test corpus holds the attested tap-web document itself, unmodified (image `sha256:a9149a88…`, `specVersion` 1.7, `serialNumber urn:uuid:90f083a0-…`, 192 components, Syft 1.51.0), so every number below is checkable.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-sbom-parse-1 | Pure And Django-Free | Implemented | The `sbom` package imports with Django's modules blocked, and a call opens no socket or file. | `tests/test_sbom_parse.py::TestPureAndDjangoFree` (a subprocess with Django blocked by a meta-path finder, `open`, sockets and the clock replaced by refusals while the corpus is parsed; a second test proves the block fires). "Unset settings" is not "no Django": the test blocks the import. |
| req-computing-core-sbom-parse-2 | Deterministic | Implemented | Parsing the same bytes twice, and parsing a document with its components reordered, yields identical batches. | `tests/test_sbom_parse.py::TestDeterministic`. The document row is excluded when components are reordered, because its digest is over the bytes and the bytes changed. |
| req-computing-core-sbom-parse-3 | The Real Document | Implemented | The corpus document yields 102 apk, 71 pypi and 7 npm packages, 3 libraries (`openssl-fips-provider`, `uv`, `uvx`), 1 operating system (`wolfi` `20230201`), 72 source packages, 1 `sbom_document`, 450 `REQUIRES_PACKAGE` edges, and no unresolved reference. | `tests/test_sbom_parse.py::TestTheRealDocument`. Counts read 2026-10-15 from the document and now asserted by the test. The 72 source packages are the distinct `(origin name, version)` pairs of the 102 apk components; the 70 distinct `syft:metadata:originPackage` values are the count of names (two names, `openssl` and `postgresql-18`, are two versions each). The 7 npm packages are 15 components: seven packages are listed 2-3 times (the same purl under different `package-id`s), which `Duplicates` makes one node each. The 450 edges are the 457 `dependsOn` entries with those duplicates collapsed. The apk database read earlier counted 69 sources on an older image. |
| req-computing-core-sbom-parse-4 | Source Packages Are Drawn | Implemented | Every apk package draws `DERIVES_FROM_SOURCE_PACKAGE`; a package with no stated origin is its own origin. `libssl3` and `libcrypto3` (3.6.4-r8) resolve to one `openssl` 3.6.4-r8 source package, the same node, and NOT to the `openssl` 3.6.5-r2 source package that the `openssl` and `openssl-dev` packages resolve to; likewise `postgresql-18` resolves to two source packages (18.6-r4, 18.6-r5). | `tests/test_sbom_parse.py::TestSourcePackagesAreDrawn`, including `::test_the_two_origins_whose_members_do_not_share_a_version_are_two_nodes_each`, which pins `openssl` and `postgresql-18`. Corrected 2026-10-15: this row first said `libssl3`, `libcrypto3` and `openssl` resolve to one source package, on the claim that an origin's members share a version, which the corpus document contradicts. A join from a finding to a source package goes by origin name. |
| req-computing-core-sbom-parse-5 | Matching Fields Survive | Implemented | `libssl3` keeps its purl with `arch`, `distro` and `upstream`, its `cpe`, and its three `cpe_candidates`; `openssl-fips-provider` keeps its `cpe`. | `tests/test_sbom_parse.py::TestMatchingFieldsSurvive`. The reason: `req-computing-core-package-6`. |
| req-computing-core-sbom-parse-6 | Unreadable Is Refused, Not Empty | Implemented | A non-JSON body, a body over the size cap, one nested past the depth cap, and a document that is not CycloneDX each raise `SbomParseError`; none returns an empty batch. | `tests/test_sbom_parse.py::TestUnreadableIsRefusedNotEmpty`. |
| req-computing-core-sbom-parse-7 | CycloneDX 1.4 To 1.7 Only | Implemented | `specVersion` 1.4, 1.5, 1.6 and 1.7 parse; 1.3 and earlier and SPDX are refused naming the format. SPDX 3 is a later requirement. | `tests/test_sbom_parse.py::TestCycloneDxOneFourToOneSeven`. Syft v1.46+ can emit SPDX 3.0.1 and Grype 0.120.1 reads it; Trivy 0.76.0 reads CycloneDX 1.7 but not SPDX 3 (both read 2026-10-15). |
| req-computing-core-sbom-parse-8 | Skips Are Counted | Implemented | A component with no name or version, and a `dependsOn` that names a non-package or an unlisted component, are not silently dropped: the report lists each count with its reason. | `tests/test_sbom_parse.py::TestSkipsAreCounted`. |
| req-computing-core-sbom-parse-9 | Digest Over The Exact Bytes | Implemented | `sbom_document.content_digest` is the SHA-256 of the bytes passed in, not of a re-serialisation. | `tests/test_sbom_parse.py::TestDigestOverTheExactBytes`. |
| req-computing-core-sbom-parse-10 | Only A Verified Document Is Parsed | Implemented | `parse_cyclonedx(data, host_id=, verification=)` requires a `Verification`; omitting it is a `TypeError`, a value that is not one is a `ValueError`, and only a `verified` outcome parses (it sets `verified` true and `signer` on the row). Any other outcome raises `ValueError` before a byte of the body is read. A `verified` `Verification` must name a non-empty signer. | `tests/test_sbom_verification.py::TestOnlyAVerifiedDocumentIsParsed`, `::TestTheOutcomeMapsToTheTriState`. From `req-cicd-sbom-22-2`, `-22-9` and `-24-6`: there is no default, so no caller parses an unverified document by leaving an argument out. |
| req-computing-core-sbom-parse-11 | A Refused Document Is Still Recorded | Implemented | `record_document(data, verification=, subject_digest=)` returns a batch of exactly the `sbom_document` row and no other row, and no `DESCRIBES_HOST` edge: a refused or unchecked record is metadata only and is not reachable from the host (a verified, parsed document does get that edge). Nothing in the body is read or JSON-parsed (`req-cicd-sbom-24-6`): the row is the SHA-256 of the exact bytes, the caller's outcome (`verified` false for `refused`, null for `not-observable`), the failing check in `verification_note`, and the caller's `subject_digest`; `format` is `unknown`, `spec_version` and `serial_number` are empty, `revision` is 1, `component_count` is 0. A readable body and an unreadable one give the same row apart from the digest. A body that is not `bytes` or `bytearray` is a `TypeError`. A refused or unchecked document is never `current` (`req-computing-core-sbom-document-7`). | `tests/test_sbom_verification.py::TestARefusedDocumentIsStillRecorded`; through the importer `tests/test_sbom_import.py::TestARefusedDocumentIsRecordedOnTheGrid`. |

### SBOM Vulnerabilities
----
RID: `req-computing-core-sbom-vulns`

Status: `Implemented`

`parse_cyclonedx_vulnerabilities(data: bytes, *, verification) -> VulnerabilityBatch` reads the `vulnerabilities[]` of a CycloneDX document that CI has scanned: revision 2 and later of an image's SBOM (the same `serialNumber`, `version` + 1), signed by `sbom-vulnerability-evidence.yml` (tap `req-cicd-sbom-17` to `-20`, `-32`). Revision 1 is packages only. George ruled 2026-10-19 that computing_core performs this logic and that github_core calls it to write the compliance vocabulary, so the reader returns neutral records and imports nothing from `compliance_core`: a plugin that owns a vocabulary maps the records to it, and this one takes no sideways dependency.

#### Implementation

**What the document carries (read 2026-10-19 from the verified revision 2 of `ghcr.io/unified-systems-com/tap-web@sha256:a9149a88…`, 94 entries, 27 distinct ids).** One entry per (canonical vulnerability id, component), by tap `req-cicd-sbom-18-3`. `id` is the CVE id, else the GHSA id the scanner named; `references[]` holds every other id. `affects[].ref` is the `bom-ref` of the document's own component (tap `req-cicd-sbom-18-9`); the reader resolves it against the document and never against a scanner's refs. `ratings[]` holds CVSS (`method` `CVSSv31`, `CVSSv4`, ... with `source`, `score`, `vector`), the SSVC assessment (`method` `SSVC`), the KEV listing (`CISA KEV Catalog`) and EPSS (`FIRST`, `justification` `EPSS`). `properties[]` carries `tap:kev:*`, `tap:epss:*`, `tap:ssvc:*`, `tap:cve-record:*` and `tap:fix:*`, each from the source CI fetched that run. `tools.components` names the detecting tool (`grype` `0.120.1`). `metadata.properties` carries the KEV catalog stamp, the scanner database build time and `tap:revision:previous-content-digest`.

**Revision 3 adds the record's identity facts (read 2026-10-19 from the verified revision 3, serial `urn:uuid:90f083a0-…`, 94 entries).** Each entry now carries `published` (the CVE record's `datePublished`, else the advisory's `published_at`), `updated`, a `description` filled from Grype, else the CVE record, else the advisory, `advisories[]` (`{title, url}`: `CVE Record` and/or `GitHub Advisory`) and the property `tap:title` (the record's title, else the advisory's, cut by CI at 100 characters with a trailing `...`). The 24 GHSA-only entries are filled from their advisories. A revision 2 document has none of these, so they stay `None` there.

**What it still does not carry, so stays `None`.** An entry with no `tap:ssvc:*` (the 24 GHSA-only ids have no CVE record, so no SSVC and no EPSS) and, unless the scanner listed CWEs, no CWE. A KEV answer of `not-observed`, or no `tap:kev:listed` property, is `Kev` of `None`, never `listed=False`. `source.url` is the scanner's own data source and is kept as `source_url`, never as the record URL.

**Mapping.**

| in the document | in the record |
| --- | --- |
| entry `id` | `VulnerabilityRecord.vuln_id`; the entry's `references[].id` are `aliases` (`()` when it lists none) |
| entry `description` | `description` (first non-empty, entries ordered by their first `affects` ref; the precedence is CI's) |
| `tap:title` | `title` |
| `published` | `published_at` (an RFC 3339 date-time with a zone, else `None` with a note) |
| `advisories[]` | `advisories`; `record_url` is the `CVE Record` link, else the first other advisory link (a GHSA-only id's record is its advisory), else `None` |
| `ratings[]` with a CVSS `method` | `cvss`: the newest CVSS version listed, its highest score, then the lowest source name; `version` from the method (`CVSSv31` is `3.1`), `source` the rating's source name |
| `cwes[]` | `cwes` as `CWE-<n>`; `()` only when `tap:cve-record:status` is `observed`, else `None` |
| `tap:ssvc:*` | `ssvc` (exploitation, automatable, technical impact, assessed-at, version) |
| `tap:kev:listed` and `tap:kev:*` | `kev`: `listed` true/false/`None`; the catalog version of a `false` answer is the document's `tap:kev:catalog-version` |
| the `FIRST` rating and `tap:epss:*` | `epss` (score, percentile, date) |
| `updated`, else `tap:cve-record:date-updated` | `record_updated_at` |
| `affects[]` | one `VulnerabilityMatch` per (vulnerability, component node); `component` is the natural key of the node `parse_cyclonedx` makes from that component |
| `tap:fix:versions`, `tap:fix:state` | `fixed_versions` (`()` for `not-fixed` or `wont-fix`, `None` when unknown), `fix_state` |
| `analysis.state` | `analysis_state`; `resolved`, `resolved_with_pedigree`, `false_positive` and `not_affected` make `exposed` false |
| `tools.components` | each match's `detectors`, and the batch's `detectors` |

**Component identity is `parse_cyclonedx`'s.** The kind and natural key of a component come from one function, `classify_component`, which `parse_cyclonedx` also calls to build its nodes, so a match cannot name a node the parser would not make. A package or library is keyed `(ecosystem, name, version)`, an operating system `(os_id, version_id, build_id)`. `ComponentKey.entity_type` and `.key` are what a caller hands the grid to find the row (a GRIFT edge endpoint by `from_key`).

**Absent is not empty.** A document with no `vulnerabilities` key was never scanned and is refused with `SbomParseError`; `"vulnerabilities": []` was scanned and returns an empty batch. Inside a record, `None` is not said and an empty value is looked-and-found-none.

**Several entries for one id.** The facts about an id belong to the id, so its entries should agree. Where they do not, ratings are pooled, a KEV listing wins over its absence, every other fact is the first in ref order, and the report names the disagreement.

**Same guarantees as `parse_cyclonedx`.** Pure and Django-free; only a `verified` outcome is read (`TypeError` without one, `ValueError` for any other, before a byte is read); the size, depth and component caps apply, plus a cap of 100,000 entries; the digest is over the exact bytes and equals the `sbom_document` row's `content_digest`; equal input gives equal output; every skipped entry or `affects` is counted with its reason.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-sbom-vulns-1 | Pure And Django-Free | Implemented | The reader imports with Django's modules blocked and a call opens no socket or file and reads no clock. | `tests/test_sbom_vulnerabilities.py::TestPureAndDjangoFree`, through the same blocking probe as `req-computing-core-sbom-parse-1`. |
| req-computing-core-sbom-vulns-2 | Only A Verified Document Is Read | Implemented | `verification` is required: omitting it is a `TypeError`, a value that is not a `Verification` or an outcome other than `verified` is a `ValueError` raised before a byte of the body is read. | `tests/test_sbom_vulnerabilities.py::TestOnlyAVerifiedDocumentIsRead`. The gate is `require_verified`, the function `parse_cyclonedx` calls. |
| req-computing-core-sbom-vulns-3 | Never Scanned Is Refused, Scanned Clean Is Empty | Implemented | A document with no `vulnerabilities` key raises `SbomParseError`; one with `"vulnerabilities": []` returns a batch with no records and no matches. A non-array value is refused. | `tests/test_sbom_vulnerabilities.py::TestNeverScannedIsRefusedScannedCleanIsEmpty`. Revision 1 of the tap-web document is the real never-scanned case. |
| req-computing-core-sbom-vulns-4 | A Match Names A Node The Parser Makes | Implemented | Every match's `ComponentKey` is the key of a package, library or operating-system node that `parse_cyclonedx` emits for the same bytes; the kind and key come from the shared `classify_component`. | `tests/test_sbom_vulnerabilities.py::TestAMatchNamesANodeTheParserMakes`, over all 94 matches of the real document. |
| req-computing-core-sbom-vulns-5 | The Real Document | Implemented | Revision 2 of the tap-web document (`serialNumber urn:uuid:90f083a0-…`, image `sha256:a9149a88…`) yields 27 vulnerability records, 94 matches (81 on packages, 13 on libraries), one detector (`grype` `0.120.1`), nothing skipped, and the document facts (revision 2, produced `2026-10-16T19:30:31Z`, previous digest `sha256:e96d02cd…`). | `tests/test_sbom_vulnerabilities.py::TestTheRealDocument`. Counts read 2026-10-19 from the document and asserted by the test. |
| req-computing-core-sbom-vulns-6 | Absent Is Declared, Never Invented | Implemented | A record keeps `None` for every fact the document does not carry: a GHSA-only record has no SSVC or EPSS; an entry with no `FIRST` rating has no `epss`; revision 2, which predates `published`, `tap:title` and `advisories[]`, yields `None` for `title`, `published_at` and `record_url`. `kev` is `None` for `not-observed` and `listed=False` only when the catalog was read. | `tests/test_sbom_vulnerabilities.py::TestAbsentIsDeclaredNeverInvented`. |
| req-computing-core-sbom-vulns-7 | One CVSS Rule | Implemented | Of the CVSS ratings an id carries, the record holds the newest version, its highest score, ties to the lowest source name; a record with no CVSS rating has `cvss` `None`. | `tests/test_sbom_vulnerabilities.py::TestOneCvssRule`. The rule reads the document only. |
| req-computing-core-sbom-vulns-8 | KEV And Fix Are Read As Published | Implemented | A listed entry yields its date added, due date, required action, ransomware use and catalog version; dates that are not `YYYY-MM-DD` are left `None` with a note. `fixed_versions` is the sorted list, `()` for `not-fixed`/`wont-fix`, `None` when unknown. | `tests/test_sbom_vulnerabilities.py::TestKevAndFixAreReadAsPublished`. Synthetic entries: the real document lists no KEV vulnerability. |
| req-computing-core-sbom-vulns-9 | Skips Are Counted | Implemented | An entry with no id or an id over 128 characters, an `affects` naming no listed component, one naming a component that becomes no node, and one listing no affected version are not dropped silently: the report counts each with its reason. | `tests/test_sbom_vulnerabilities.py::TestSkipsAreCounted`. |
| req-computing-core-sbom-vulns-10 | Deterministic | Implemented | The same bytes twice, and the same document with its entries and components reordered, give identical batches apart from the document digest. | `tests/test_sbom_vulnerabilities.py::TestDeterministic`. |
| req-computing-core-sbom-vulns-11 | Unreadable Is Refused, Not Empty | Implemented | A non-JSON body, one over the size cap, a document that is not CycloneDX and one with more entries than the cap each raise `SbomParseError`. | `tests/test_sbom_vulnerabilities.py::TestUnreadableIsRefusedNotEmpty`. |
| req-computing-core-sbom-vulns-12 | Digest Over The Exact Bytes | Implemented | `DocumentInfo.content_digest` is the SHA-256 of the bytes passed in and equals the `content_digest` of the `sbom_document` row `parse_cyclonedx` makes from them. | `tests/test_sbom_vulnerabilities.py::TestDigestOverTheExactBytes`. |
| req-computing-core-sbom-vulns-13 | Entries Of One Id Are Pooled, Disagreement Is Named | Implemented | Where the entries of one id disagree on description, SSVC, EPSS or KEV, the first (a KEV listing over its absence) is kept and a report note names the id and the fact. | `tests/test_sbom_vulnerabilities.py::TestEntriesOfOneIdArePooled`. |
| req-computing-core-sbom-vulns-14 | A VEX Statement Is Carried | Implemented | An entry with `analysis.state` `not_affected`, `false_positive`, `resolved` or `resolved_with_pedigree` yields a match whose `exposed` is false; any other state or none leaves it true. | `tests/test_sbom_vulnerabilities.py::TestAVexStatementIsCarried`. The CI workflow writes no `analysis` today; the field is read so a later VEX revision is not mistaken for an open finding. |
| req-computing-core-sbom-vulns-15 | Title, Publication Time And Record Link | Implemented | Over the real revision 3: all 27 records have a `title`, a `published_at` and a `record_url`; a CVE id's `record_url` is its `CVE Record` link and a GHSA-only id's is its `GitHub Advisory` link; every advisory link is kept in `advisories`; `record_updated_at` is the entry's `updated`. A `published` that is not an RFC 3339 date-time is `None` with a note. | `tests/test_sbom_vulnerabilities.py::TestTitlePublicationAndRecordLink`. |

### SBOM Builder
----
RID: `req-computing-core-sbom-build`

Status: `Implemented`

`build_cyclonedx(packages, libraries, operating_system, *, requires=()) -> bytes` is the parser run backwards (`requires` is the optional list of `(package key, package key)` pairs that become `dependencies`, because `REQUIRES_PACKAGE` edges are not package properties; the inputs are mappings of the node properties, so the function stays Django-free): it turns packages on the grid into a CycloneDX document a scanner can read. It exists for the Grype plugin, which builds a document from what the grid says is deployed, scans it, and writes the findings back onto the same packages. The document is a throwaway input; it is not stored (tap#1035), and the caller chooses which packages go in (every package a host installs, say).

#### Implementation

**CycloneDX 1.6.** Every reader tried takes 1.6. Trivy 0.70.0 could not decode 1.7 ("invalid specification version", the cause of tap#1036), and Grype read the 1.6 documents built for the measurement above.

**What it writes.** Per package: `type: library`, `name`, `version`, the whole `purl`, `cpe`, and each `cpe_candidates` entry as a `syft:cpe23` property, because Grype reads those (the build in the table above recovered all 91 findings with them and 89 without). Libraries are included, since the provider matches on its CPE alone. The operating system goes in as an `operating-system` component with `syft:distro:id` and `syft:distro:versionID`. `REQUIRES_PACKAGE` becomes `dependencies`. `bom-ref` is the purl where there is one and a deterministic handle where there is not.

**What it never does.** It writes nothing to the grid and nothing to disk, and the same inputs give the same bytes. Two input rows with one `(ecosystem, name, version)` are one component (the one with the smallest purl is written). A package the grid holds with no `purl` is written with a minimal `pkg:<ecosystem>/<name>@<version>`, or a reader could not tell its package manager, and it carries no `upstream=`, so a package with no `purl`, or one whose purl lacks `upstream=`, comes back from a round trip as its own origin rather than under the source package the grid drew for it. The output is ASCII.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-sbom-build-1 | The Matching Fields Are Emitted | Implemented | The output carries each package's whole purl, `cpe`, every `cpe_candidates` entry as `syft:cpe23`, the libraries, and the operating system's distro properties. | `tests/test_sbom_build.py::TestTheMatchingFieldsAreEmitted`. |
| req-computing-core-sbom-build-2 | Round Trip | Implemented | `parse(build(parse(corpus)))` yields the same packages, libraries, source packages and edges as `parse(corpus)`. | `tests/test_sbom_build.py::TestRoundTrip`. The source-package edges survive through the `upstream=` qualifier, so the builder must write it; a package with no purl or no `upstream=` loses its source package on the round trip (it comes back as its own origin; see Builder, what it never does). |
| req-computing-core-sbom-build-3 | The Scanner Agrees | Implemented | Grype run on the built document matches the same 91 findings over 27 vulnerability ids as on the corpus document. | **CI skips this test**: it needs a Grype binary and a vulnerability database (`GRYPE_BIN` or `grype` on PATH; it sets `GRYPE_DB_AUTO_UPDATE=false`), which the plugin CI does not have. The evidence for the Implemented status is the hand run on 2026-10-15, not a CI result. `tests/test_sbom_build.py::TestTheScannerAgrees`. Run by hand 2026-10-15 with Grype v0.120.1 (database built 2026-10-15T06:30Z) on the corpus and on the built document: 91 matches over 27 vulnerability ids on each, none missing and none extra. The test compares the two matches sets rather than asserting 91, because the database moves. |
| req-computing-core-sbom-build-4 | Throwaway And Deterministic | Implemented | The function performs no database write and no file write, and two calls on the same inputs return identical bytes. | `tests/test_sbom_build.py::TestThrowawayAndDeterministic`. |

### Protocol Scope
----
RID: `req-computing-core-protocols`

Status: `Proposed`

v0 stops just above layer four and does not yet commit to concrete application protocols.

#### Implementation

The plugin includes a generic `application_protocol` model as the jump-off point for later work, but it does not yet define dedicated models for HTTP, HTTPS/TLS, DNS, SSH, or similar protocols.

This keeps the plugin usable for connection and dependency modeling without forcing premature protocol taxonomy decisions.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-protocols-1 | Generic Protocol Model | Proposed | The plugin includes a generic `application_protocol` model. | |
| req-computing-core-protocols-2 | Concrete Protocols Deferred | Proposed | Specific protocols are deferred from v0. | |

### Edge Types
----
RID: `req-computing-core-edges`

Status: `Proposed`

The plugin favors a small but expressive edge family over generic catch-all edges.

#### Implementation

> **Candidate set pruned (pre-eviction, 2026-07-08).** These are aspirational candidate
> edge types, not a built inventory. Seven scaffolded-but-never-emitted edge definitions
> (`HOSTS`, `RUNS_ON`, `HAS_IP`, `AVAILABLE_AT`, `LISTENS_ON`, `CONNECTS_TO`, `PAIRED_WITH`)
> were deleted rather than frozen into the release tag as speculative surface. The only
> edges computing_core actually ships today are the ones consumers emit / seed:
> `GENERATES_FILE` (and, until 2026-10-02, `FETCHES_DOCUMENT` and `HOSTS_DOCUMENT`; see below),
> and since 2026-10-08 `DEFINES_OS_USER`, `DEFINES_OS_GROUP` and `MEMBER_OF_GROUP`
> ([OS Accounts And Groups](#os-accounts-and-groups)), and since 2026-10-14 `INSTALLS_PACKAGE`,
> `SHIPS_LIBRARY`, `LOADS_LIBRARY`, `RUNS_OPERATING_SYSTEM`, `CARRIES_CRYPTO_PROVIDER` and (since 2026-10-15) `DERIVES_FROM_SOURCE_PACKAGE`
> ([Software Inventory Edges](#software-inventory-edges)), and since 2026-10-19 `RUNS_PROGRAM` and `RUNS_IMAGE`
> ([Runtime Edges](#runtime-edges)) and `APPLICATION_FLOW_SOURCE` and `APPLICATION_FLOW_DESTINATION`
> ([Application Flow](#application-flow-modeling)).
> The candidates below return — correctly named per the add-edge skill — when a collector
> actually emits them.
>
> **Renamed 2026-09-10 (computing-core#4).** `HOSTED_BY` (document -> host) is now
> `HOSTS_DOCUMENT` (host -> document — the host is the actor, so the direction flipped) and the
> bare verb `FETCHES` is now `FETCHES_DOCUMENT`; both failed core's edge-naming check
> (`req-tap-plugin-edge-naming`: trailing preposition, bare verb) and were renamed rather than
> baselined. Migration `0003_retire_renamed_edge_types` deletes rows of the retired types on an
> upgraded grid; the next collection / seed re-emits them under the new names. Consumers
> (samsite's KEV seed + collector) move in their own follow-on.
>
> **Retired 2026-10-02 (computing-core#25; George, highbar Q133).** `FETCHES_DOCUMENT` and
> `HOSTS_DOCUMENT` are deleted, not renamed. An HTTP interaction will be modelled as a VERB NODE
> (get, put, patch, ...) with its own edges, originator -> verb node -> destination, rather than
> as one edge from the fetcher to the document; `HOSTS_DOCUMENT` (`web_host -> web_document`)
> goes with it. Migration `0005_retire_document_edge_types` deletes rows of both types on an
> upgraded grid; the `web_host` and `web_document` nodes stay. This is a breaking change for
> samsite, which seeds `HOSTS_DOCUMENT`, emits `FETCHES_DOCUMENT` from its compliance collector
> and draws `HOSTS_DOCUMENT` in its landing projection; it pins `<0.5` and moves in its own
> follow-on.

Representative relationship categories for v0 include:

| Category | Candidate Edge Types | Description |
| --- | --- | --- |
| Structural | `HOSTS`, `RUNS_ON`, `CONTAINS`, `MOUNTS`, `BACKS`, `ATTACHED_TO` | Containment, hosting, and attachment relationships |
| Runtime | `RUNS_PROGRAM` and `RUNS_IMAGE` (built 2026-10-19), `SPAWNS`, `LISTENS_ON`, `CONNECTS_TO` | Runtime execution and endpoint/session relationships |
| Networking | `HAS_IP`, `AVAILABLE_AT`, `BELONGS_TO_SUBNET`, `ROUTES_VIA` | Interface and address relationships, including scanner-visible observations |
| Protocol | `USES_PROTOCOL`, `RELIES_ON_CONNECTION` | Protocol attachment and dependency |

Web-native relationships have no edge type today: the retired `HOSTS_DOCUMENT` /
`FETCHES_DOCUMENT` pair is replaced, when it is built, by HTTP verb nodes (see the retirement
note above).

The exact edge set should remain expressive and specific enough that graph queries read naturally. Reuse matters, but v0 should lean toward semantic clarity rather than collapsing too much behavior into generic edges.

The initial networking shape should support both structural and scanner-visible views:

- `program -LISTENS_ON-> port`
- `port -ATTACHED_TO-> network_interface`
- `port -AVAILABLE_AT-> ip_address`
- `network_interface -HAS_IP-> ip_address`

This allows TAP to represent:

- a richer host-centric view when interfaces are known
- a thinner externally observed view when only IP, port, and program information are available

`AVAILABLE_AT` should not require `ATTACHED_TO` to exist. `HAS_IP` is the stronger structural claim when a concrete interface is known.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-edges-1 | Expressive Edge Family | Proposed | The plugin uses a small expressive edge family rather than relying primarily on generic reusable edges. | |
| req-computing-core-edges-2 | Session Directionality | Proposed | Edge naming and direction preserve the intended client-to-server session semantics. | |
| req-computing-core-edges-3 | Dimensioned Edges | Proposed | Every declared edge type carries meaningful `tap.computing` default dimensions. | |
| req-computing-core-edges-4 | Scanner Visible Port Shape | Proposed | The edge model supports port-to-IP observations without requiring a network interface node. | |
| req-computing-core-edges-5 | Program To Port Listening | Proposed | The model expresses that a program listens on a port independently of whether interface details are known. | |

#### Open Questions

The precise boundary between "expressive enough" and "too many unique edge types" should be revisited once the first real computing graphs are queried in practice.

Should `AVAILABLE_AT` be interpreted strictly as an observed externally reachable binding, or should it also cover local-only availability claims from host telemetry sources? v0 can start broad, but future protocol and perspective work may want a sharper distinction.

### Reference Data
----
RID: `req-computing-core-reference`

Status: `Proposed`

The plugin may seed small but useful generic reference data.

#### Implementation

The first reference-data candidate is dimension nodes for the `tap.computing` category values used by the plugin. Those nodes should describe what each category means and why it exists.

The plugin may later seed small generic vocabularies such as TCP states or protocol categories if doing so proves useful, but v0 should stay conservative and avoid creating taxonomy data without a concrete graph use case.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-reference-1 | Dimension Nodes Seeded | Proposed | The plugin seeds dimension nodes describing the chosen `tap.computing` categories. | |
| req-computing-core-reference-2 | Minimal Reference Surface | Proposed | v0 seed data stays small and justified by actual graph use. | |

### Plugin Validation
----
RID: `req-computing-core-validation`

Status: `Proposed`

The plugin should pass TAP's centralized plugin validation system and encourage deeper validation before public release.

#### Implementation

The plugin should pass:

- `structure` validation during early authoring
- future `loads` and `runs` validation before the plugin is considered ready for broader publication

This matters especially for a plugin with many concrete models, where importability alone does not prove that migrations, tables, and runtime behavior are sound.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-computing-core-validation-1 | Structure Validation Required | Proposed | The plugin must pass TAP plugin structure validation. | |
| req-computing-core-validation-2 | Deeper Validation Recommended | Proposed | Authors should run future `loads` and `runs` validation before publishing the plugin widely. | |

### v0 Non-Goals
----
RID: `req-computing-core-nongoals`

Status: `Proposed`

This specification does not define:

- physical hardware modeling
- cloud-provider-native resource types
- packet-level or hop-level network modeling
- UDP or IP flow modeling
- concrete application-protocol models such as HTTP, DNS, or TLS
- generic `service` or `application` models
- cross-plugin dependency contracts

These are important future concerns, but they are intentionally outside the first Computing Core pass.

## Future Work

- Split networking and protocol concerns into dedicated plugins if the graph grows deep enough to justify that boundary.
- Add richer protocol models above `application_protocol`.
- Add `udp_flow` if real use cases justify it.
- Explore packet-hop or path modeling when TAP has a stable need to reason about concrete network hops.
- Define a clearer relationship between `program`, `process`, and any future `application` or `service` concepts.
