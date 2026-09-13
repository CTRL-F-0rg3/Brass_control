
# Brass Control (`brass_control`)

`brass_control` is a lightweight, low-level version control CLI client designed to manage custom repository objects, compress revisions into packfiles, and synchronize directly with a dedicated `brass_control_server` over SSH.

---

## Release Versioning Scheme

The project follows a structured, custom versioning syntax to guarantee strict compatibility between clients and servers.

### Version String Format
```text
w-2026.09.a122-base
│   │    │   │    └─ Build Tag / Stage (e.g., base, stable, dev)
│   │    │   └────── Compatibility Identification ID (e.g., a122)
│   │    └────────── Release Month (09 = September)
│   └─────────────── Release Year (2026)
└─────────────────── Version Edition Indicator ('w' = Work/Edition)

```

### Components Breakdown

| Element | Example | Description |
| --- | --- | --- |
| **Prefix** | `w` | Version edition year marker. |
| **Year** | `2026` | The calendar year of the release. |
| **Month** | `09` | Two-digit calendar month of the release. |
| **Compat ID** | `a122` | **Critical:** Target protocol and data model compatibility ID. |
| **Tag** | `base` | Release type identifier (`base` indicates the core baseline release). |

### Compatibility Matching

Before running sync operations (`push`, `fetch`), ensure both **`brass_control`** and **`brass_control_server`** share the **exact same Compatibility Identification ID** (e.g., `a122` matching `a122`). If the client and server IDs differ, wire protocols or packfile formats may mismatch.

---

## CLI Command Reference

### Local Version Control

* **`brass init`**
Initializes a new `brass_control` workspace and creates local object directory structures.
* **`brass add <path>`**
Stages files or directories into the index for the next commit.
* **`brass commit -m "<message>"`**
Creates a immutable commit node referencing the current staged snapshot.
* **`brass status`**
Displays the current workspace state, untracked files, and staged changes.
* **`brass pack`**
Packs individual local objects into a single compressed `.pack` archive for network transmission.

### Remote Network Operations

* **`brass push <server_address:port> <branch_or_ref>`**
Establishes an SSH connection with the server and streams the packed repository delta over port `2222`.

---

## Build & Usage

```bash
# Build release binary
cargo build --release

# Initialize repository in current path
./target/release/brass_control init

# Stage and commit changes
./target/release/brass_control add .
./target/release/brass_control commit -m "Initial baseline revision"

# Push pack to remote server
./target/release/brass_control push 127.0.0.1:2222 main

```

```

---

### 2. Server Repository: `brass_control_server/README.md`

```markdown
# Brass Control Server (`brass_control_server`)

`brass_control_server` is a high-performance daemon providing a dual-layer interface: an asynchronous **SSH transport service** (via `russh`) for repository network streaming, and a public **REST API** (via `axum`) for project management and observability.

---

## Release Versioning Scheme

The server uses the same deterministic release versioning convention as the client to ensure complete protocol parity.

### Version String Format
```text
w-2026.09.a122-base

```

### Matching Client & Server Compatibility

To verify that your setup is fully compatible:

1. Identify the **Compatibility ID** (e.g., `a122`) in your server build.
2. Verify that the client build matches `a122`.
3. Do not connect client `a122` to a server running `a123` or older legacy formats, as wire serialization structures may differ.

---

## Public REST API Reference

The server exposes a public HTTP REST API on port `8080`.

### Endpoints

| Method | Endpoint | Description | Sample Payload / Response |
| --- | --- | --- | --- |
| `GET` | `/api/v1/repos` | Lists all bare repositories with object counts and total disk sizes. | `{"success": true, "data": [...]}` |
| `POST` | `/api/v1/repos` | Creates a new bare repository on the server. | `{"name": "new_project"}` |
| `DELETE` | `/api/v1/repos/:name` | Deletes a repository and all its stored objects. | `{"success": true, "message": "..."}` |

### cURL Examples

```bash
# List remote repositories
curl http://localhost:8080/api/v1/repos

# Create a new bare repository
curl -X POST http://localhost:8080/api/v1/repos \
  -H "Content-Type: application/json" \
  -d '{"name": "project_alpha"}'

# Delete a repository
curl -X DELETE http://localhost:8080/api/v1/repos/project_alpha

```

---

## SSH Remote Administration Commands

Administrators can execute management actions directly over SSH (Port `2222`):

```bash
# Query repository list over SSH
ssh -p 2222 user@localhost "brass-admin repo list"

```

---

## Execution

```bash
# Run server (starts HTTP on 8080 and SSH on 2222)
cargo run --release

```
