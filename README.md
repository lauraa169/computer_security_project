# Computer Security Project

### TODO

## Predefined Users

Access control policies are statically provisioned at server startup using datasets located in the `data/` directory (`users.json`, `user_roles.json`, `role_perms.csv`, `mac_labels.json`, and `dac_owners.csv`). No users, roles, or clearances are created or altered dynamically at runtime.

| Username | Assigned Roles (RBAC) | Clearance Level (MAC) | Group Memberships (DAC) | Powers & Access Boundaries |
| :--- | :--- | :--- | :--- | :--- |
| `alice` | `professor` | `confidential` (Level 2) | `university`, `course_staff`, `faculty` | System administrator with owner privileges over `/`, `/projects`, `/projects/confidential`, and `/admin`. Cleared to access confidential materials; restricted by MAC from writing downward into `internal` or `public` resources. |
| `bob` | `student`, `TA` | `internal` (Level 1) | `university`, `course_staff` | Teaching assistant with read/write access in `/projects` and `/public`. Barred from `/admin` by both RBAC role scope and DAC permissions, and blocked by MAC from reading `confidential` resources. |
| `eve` | `student` | `public` (Level 0) | `university` | Standard student account. Owns and manages uploads within `/public`. Granted read-only inspection on `/projects`. Denied access to `/admin` and all higher-classification tiers (`internal`, `confidential`) by MAC and DAC. |

---

## Access Control Design

Authorization in the SFTP server is governed by a unified authorization gate, `PolicyEngine.authorize(user, op, full_path)`, implemented in `server/policy.py`. It simultaneously evaluates three access control models: Discretionary Access Control (DAC), Mandatory Access Control (MAC), and Role-Based Access Control (RBAC).

### 1. Operations Mapping & Default-Deny Policy
SFTP v3 protocol requests received by `server/server.py` are mapped into internal authorization operations before reaching the authorization gate:

| Protocol Request | Internal AuthZ Op (`op`) | Operational Category | Required DAC Permission Bits |
| :--- | :--- | :--- | :--- |
| `REALPATH` | `"realpath"` | Path resolution | Directory traversal (`x`) |
| `STAT`, `LSTAT`, `FSTAT` | `"stat"` | Attribute inspection | Directory traversal (`x`) |
| `OPENDIR`, `READDIR` | `"list"` | Directory enumeration | Directory read and traversal (`r`, `x`) |
| `OPEN` (read) + `READ` | `"read"` | File download | File read (`r`) |
| `OPEN` (write) + `WRITE` | `"write"` | File upload / modification | File / parent directory write (`w`) |
| `MKDIR` | `"mkdir"`, `"create"` | Directory creation | Parent directory write and traversal (`w`, `x`) |
| `REMOVE`, `RMDIR` | `"remove"` | Deletion | Directory write (`w`) |
| `RENAME` | `"rename"` | Modification | Directory write (`w`) |

**Default-Deny:** The system fails closed. Any operation not explicitly enumerated above, any resource lacking an associated policy match, or any user presenting unrecognized roles/clearances is denied by default.

### 2. Enforcement Point
Authorization occurs strictly **after** canonical path resolution inside the jail via `safe_join` and **before** any low-level operating system filesystem invocation (`os.open`, `os.mkdir`, etc.):

```text
SFTP Request -> Path Canonicalization (Jail Check) -> authorize(user, op, path) -> OS Filesystem Call -> Audit Record
```

Canonical paths passed to `authorize` are POSIX-formatted and rooted at `/` (representing the jail boundary).

### 3. Discretionary Access Control (DAC)
* **Ownership & Group Model:** Resource paths are registered in `data/dac_owners.csv` with a dedicated owner, an administrative group, a 9-character Unix-style mode string, and a pipe-separated roster of group members (`group_members`).
* **Mode String Representation:** Permissions follow the 9-character format `[owner: 0..3][group: 3..6][other: 6..9]` (e.g., `rwxr-x---`).
  * If `user == owner`, bits `[0:3]` are evaluated.
  * Else if `user in group_members`, bits `[3:6]` are evaluated.
  * Otherwise, world bits `[6:9]` apply.
* **Directory vs. File Semantics ($r/w/x$):**
  * **Files:** `r` governs file read access (`read`), and `w` governs write or overwrite access (`write`).
  * **Directories:** `x` governs traversal and attribute lookups (`stat`, `realpath`). Directory listing (`list`) requires both read and execution bits (`r`, `x`). Directory creation (`mkdir`) requires both write and execution bits (`w`, `x`) on the parent path.
* **Inheritance:** New subdirectories and files created inside a path inherit the owner, group, and mode bits of the parent path defined in `dac_owners.csv`.
* **Examples:**
  * *Owner Allow:* `alice` accesses `/projects` (`owner: alice`, mode `rwxrwx---`); owner bits `rwx` grant full read and write.
  * *Group Allow:* `bob` accesses `/projects` (`group: course_staff`, which includes `bob`); group bits `rwx` grant read, write, and directory traversal.
  * *Other Deny:* `eve` accesses `/projects`; categorized as `other`, where bits `---` deny all read, write, and traversal operations.

### 4. Mandatory Access Control (MAC)
* **Taxonomy & Clearances:** Security classifications follow a hierarchical Multi-Level Security (MLS) taxonomy loaded from `data/mac_labels.json`:
  $$\text{public (0)} < \text{internal (1)} < \text{confidential (2)}$$
* **Enforced Properties (Bell-LaPadula):**
  * **No Read Up:** A user cannot read or inspect metadata of resources classified higher than their clearance level. Read operations (`read`, `stat`, `list`, `realpath`) require:
    $$\text{User Clearance Level} \ge \text{Path Sensitivity Level}$$
  * **No Write Down:** A user cannot write to or create items in resources classified lower than their clearance level, preventing data exfiltration from high to low security zones. Write operations (`write`, `mkdir`, `remove`, `rename`) require:
    $$\text{User Clearance Level} \le \text{Path Sensitivity Level}$$
* **Storage:** Clearances and resource path labels are statically mapped in `data/mac_labels.json` under top-level `"users"` and `"paths"` dictionaries.

### 5. Role-Based Access Control (RBAC)
* **Role Mappings:** Users are mapped to one or more roles in `data/user_roles.json`. Roles are granted permissions over path prefixes via the permissions matrix in `data/role_perms.csv`.
* **Union of Roles:** Permissions are additive. If a user possesses multiple roles (e.g., `bob` holding both `student` and `TA`), the effective permission set is the union of all permissions granted across all assigned roles.
* **Path Prefix Scoping:** For each role assigned to a user, the engine identifies the longest matching resource prefix in `role_perms.csv`. Permissions from the most specific prefix match of each active role are combined into the user's total permitted action set for that request.
* **Conflict Resolution:** RBAC enforces a default-deny rule: if the requested operation is not present in the combined permitted set of actions, the request is denied.

### 6. Composition Rule & Outcome Matrix
The final access decision is the logical conjunction of all three security models:
$$\text{Final Decision} = \text{DAC} \land \text{MAC} \land \text{RBAC}$$

The authorization gate executes checks in sequence (`DAC -> MAC -> RBAC`). If any model denies the request, execution terminates immediately, logging and returning that model's specific denial reason.

| DAC Decision | MAC Decision | RBAC Decision | Final Gate Outcome | Example Scenario |
| :---: | :---: | :---: | :---: | :--- |
| **Allow** | **Allow** | **Allow** | **ALLOW** | `alice` executes `write` on `/projects/confidential/exam.pdf` (Owner has `w`, clearance $2 \le 2$, `professor` role has `write`). |
| **Allow** | **Deny** | **Allow** | **DENY** | `alice` executes `write` on `/public/announcement.txt` (DAC and RBAC permit, but MAC denies write-down: user `confidential` > resource `public`). |
| **Allow** | **Allow** | **Deny** | **DENY** | `bob` executes `read` on `/welcome.txt` (DAC group has `r`, MAC clearance $1 \ge 0$, but RBAC roles `student` and `TA` lack `read` under `/`). |
| **Deny** | **Allow** | **Allow** | **DENY** | `bob` executes `write` on `/projects/confidential/exam.pdf` (DAC denies: Bob is in `other` category with mode bits `---`). |

### 7. Auditing Specification
Every decision made by `authorize()` appends a single line-delimited JSON record to `server/audit.jsonl`. 

Each log entry records six mandatory fields:
* `timestamp`: ISO-8601 UTC timestamp string.
* `user`: The authenticated username initiating the operation.
* `op`: The requested SFTP operation name.
* `path`: The jail-canonicalized resource target path.
* `allowed`: Boolean outcome (`true` for grant, `false` for denial).
* `reason`: Descriptive explanation indicating the granting or blocking model.

**Sample Log Entries (`server/audit.jsonl`):**
```json
{"timestamp": "2026-11-11T13:14:02.102145+00:00", "user": "alice", "op": "write", "path": "/projects/confidential/exam_draft.pdf", "allowed": true, "reason": "Allowed by DAC, MAC, and RBAC"}
{"timestamp": "2026-11-11T13:14:05.419082+00:00", "user": "alice", "op": "write", "path": "/public/leak.txt", "allowed": false, "reason": "MAC deny: MAC: Denied write down (user confidential > path public)"}
{"timestamp": "2026-11-11T13:14:08.882103+00:00", "user": "eve", "op": "read", "path": "/projects/confidential/exam.pdf", "allowed": false, "reason": "DAC deny: DAC: Denied for other lacking 'r' bit"}
{"timestamp": "2026-11-11T13:14:12.012543+00:00", "user": "bob", "op": "read", "path": "/welcome.txt", "allowed": false, "reason": "RBAC deny: RBAC: Denied, operation 'read' not granted by roles ['student', 'TA']"}
```

## TODO