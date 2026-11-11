import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple


CLEARANCE_ORDER = {"public": 0, "internal": 1, "confidential": 2}
READ_OPS = {"realpath", "stat", "list", "read"}
WRITE_OPS = {"mkdir", "write", "remove", "rename", "create"}


class PolicyEngine:
    def __init__(self, data_dir: str = "data", audit_path: str = "server/audit.jsonl"):
        self.data_dir = Path(data_dir)
        self.audit_path = Path(audit_path)

        # internal state populated during _load_all()
        self.user_roles: dict[str, list[str]] = {}
        self.role_perms: dict[str, dict[str, set[str]]] = {}
        self.mac_users: dict[str, str] = {}
        self.mac_paths: dict[str, str] = {}
        self.dac_rules: dict[str, dict] = {}

        self._load_all()

    def _load_all(self) -> None:
        # Load all policy data from the data directory
        self._load_user_roles()
        self._load_role_perms()
        self._load_mac_labels()
        self._load_dac_owners()

    def _load_user_roles(self) -> None:
        path = self.data_dir / "user_roles.json"
        if not path.is_file():
            raise RuntimeError(f"Fatal startup error: Missing file '{path}'")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Root must be a JSON object mapping user to roles.")
            self.user_roles = data
            print(f"[PolicyEngine] Loaded user_roles from {path}")
        except Exception as exc:
            raise RuntimeError(f"Fatal startup error: Malformed '{path}': {exc}")

    def _load_role_perms(self) -> None:
        path = self.data_dir / "role_perms.csv"
        if not path.is_file():
            raise RuntimeError(f"Fatal startup error: Missing file '{path}'")
        try:
            self.role_perms = {}
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames or "role" not in reader.fieldnames:
                    raise ValueError("Missing 'role' column in CSV header.")

                action_columns = [
                    c for c in reader.fieldnames if c not in ("role", "resource")
                ]

                for row in reader:
                    role = row["role"].strip()
                    resource = row["resource"].strip()
                    actions = {
                        c for c in action_columns if row.get(c) and row[c].strip() == c
                    }

                    if role not in self.role_perms:
                        self.role_perms[role] = {}
                    self.role_perms[role][resource] = actions

            print(f"[PolicyEngine] Loaded role_perms from {path}")
        except Exception as exc:
            raise RuntimeError(f"Fatal startup error: Malformed '{path}': {exc}")

    def _load_mac_labels(self) -> None:
        path = self.data_dir / "mac_labels.json"
        if not path.is_file():
            raise RuntimeError(f"Fatal startup error: Missing file '{path}'")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "users" not in data or "paths" not in data:
                raise ValueError(
                    "Expected 'users' and 'paths' top-level keys in mac_labels.json."
                )
            self.mac_users = data["users"]
            self.mac_paths = data["paths"]
            print(f"[PolicyEngine] Loaded mac_labels from {path}")
        except Exception as exc:
            raise RuntimeError(f"Fatal startup error: Malformed '{path}': {exc}")

    def _load_dac_owners(self) -> None:
        path = self.data_dir / "dac_owners.csv"
        if not path.is_file():
            raise RuntimeError(f"Fatal startup error: Missing file '{path}'")
        try:
            self.dac_rules = {}
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    prefix = row["path"].strip()
                    members = (
                        [m.strip() for m in row["group_members"].split("|")]
                        if row.get("group_members")
                        else []
                    )
                    self.dac_rules[prefix] = {
                        "owner": row["owner"].strip(),
                        "group": row["group"].strip(),
                        "mode": row["mode"].strip(),
                        "group_members": set(members),
                    }
            print(f"[PolicyEngine] Loaded dac_owners from {path}")
        except Exception as exc:
            raise RuntimeError(f"Fatal startup error: Malformed '{path}': {exc}")

    def check_dac(self, user: str, op: str, full_path: str) -> Tuple[bool, str]:
        # determine required permission bits based on operation
        # note: 'stat' requires traversal ('x'), while 'list' typically requires both 'r' and 'x'
        if op == "read":
            required_bits = ["r"]
        elif op in ("write", "remove", "rename"):
            required_bits = ["w"]
        elif op in ("mkdir", "create"):
            required_bits = ["w", "x"]
        elif op == "list":
            required_bits = ["r", "x"]
        elif op in ("stat", "realpath"):
            required_bits = ["x"]
        else:
            return False, f"DAC: Unsupported operation '{op}'"

        # find the longest matching prefix in dac_rules
        matched_prefix = None
        for prefix in sorted(self.dac_rules.keys(), key=len, reverse=True):
            if prefix == "/" or full_path == prefix or full_path.startswith(prefix + "/"):
                matched_prefix = prefix
                break

        if not matched_prefix:
            return False, f"DAC: No matching rules found for path '{full_path}'"

        rule = self.dac_rules[matched_prefix]
        owner = rule["owner"]
        group_members = rule["group_members"]
        mode = rule["mode"]

        #select the permission bits based on user role
        if user == owner:
            relevant_mode = mode[0:3]
            category = "owner"
        elif user in group_members:
            relevant_mode = mode[3:6]
            category = "group"
        else:
            relevant_mode = mode[6:9]
            category = "other"

        # verify all required permission bits are present in the relevant mode
        for bit in required_bits:
            if bit not in relevant_mode:
                return (
                    False,
                    f"DAC: Denied for {category} lacking '{bit}' bit",
                )

        return True, f"DAC: Allowed as {category} with required permissions"

    def check_mac(self, user: str, op: str, full_path: str) -> Tuple[bool, str]:
        # get the user's clearance, default to the lowest level (public) if missing
        user_clearance_label = self.mac_users.get(user, "public")

        matched_prefix = None
        for prefix in sorted(self.mac_paths.keys(), key=len, reverse=True):
            if prefix == "/" or full_path == prefix or full_path.startswith(prefix + "/"):
                matched_prefix = prefix
                break

        if not matched_prefix:
            return False, f"MAC: No label found for path '{full_path}'"

        path_label = self.mac_paths[matched_prefix]

        # convert labels to numeric levels for comparison
        user_level = CLEARANCE_ORDER.get(user_clearance_label, 0)
        path_level = CLEARANCE_ORDER.get(path_label, 0)

        # enforce no read up (user clearence must be >= resource label)
        if op in READ_OPS:
            if user_level >= path_level:
                return True, f"MAC: Allowed read (user {user_clearance_label} >= path {path_label})"
            else:
                return False, f"MAC: Denied read up (user {user_clearance_label} < path {path_label})"

        # enforce no write down (user clearance must be <= resource label)
        elif op in WRITE_OPS:
            if user_level <= path_level:
                return True, f"MAC: Allowed write (user {user_clearance_label} <= path {path_label})"
            else:
                return False, f"MAC: Denied write down (user {user_clearance_label} > path {path_label})"

        return False, "MAC default deny"

    def check_rbac(self, user: str, op: str, full_path: str) -> Tuple[bool, str]:
        # get all the roles the user has
        roles = self.user_roles.get(user, [])
        if not roles:
            return False, f"RBAC: User '{user}' has no assigned roles"

        lookup_op = "mkdir" if op == "create" else op

        # track the longest matching path prefix found across all roles
        union_allowed_actions = set() # set to collect all allowed actions
        matched_any_role = False

        for role in roles:
            # skip if the role has no permissions defined
            if role not in self.role_perms:
                continue

            role_rules = self.role_perms[role]

            # find the longest matching prefix for THIS specific role
            best_prefix = None
            best_len = -1
            best_actions = set()

            for prefix, actions in role_rules.items():
                # check if the requested path matches the prefix
                if prefix == "/" or full_path == prefix or full_path.startswith(prefix + "/"):
                    prefix_len = len(prefix)

                    # if this is a longer prefix match than we've found before,
                    # clear previous actions and start fresh with this longer match
                    if prefix_len > best_len:
                        best_prefix = prefix
                        best_len = prefix_len
                        best_actions = set(actions)
                    # if this prefix matches our current best length (from another role),
                    # union the allowed actions together
                    elif prefix_len == best_len:
                        best_actions.update(actions)

            if best_prefix is not None:
                matched_any_role = True
                union_allowed_actions.update(best_actions)

        # if no prefix matched across all roles, deny access
        if not matched_any_role:
            return False, f"RBAC: No matching rules found for path '{full_path}'"

        # check if the requested operation is allowed by the union of actions
        if lookup_op in union_allowed_actions:
            return True, f"RBAC: Allowed via union of roles {roles}"
        else:
            return False, f"RBAC: Denied, operation '{op}' not granted by roles {roles}"

    def authorize(self, user: str, op: str, full_path: str) -> Tuple[bool, str]:
        # check each policy model in order: DAC, MAC, RBAC
        for model_name, check in [
            ("DAC", self.check_dac),
            ("MAC", self.check_mac),
            ("RBAC", self.check_rbac),
        ]:
            allowed, reason = check(user, op, full_path)
            # if any of the checks deny access, log the denial and return false
            if not allowed:
                self._write_audit(user, op, full_path, False, f"{model_name} deny: {reason}")
                return False, f"{model_name} deny: {reason}"

        # if all checks passed, log the allowance and return success
        reason = "Allowed by DAC, MAC, and RBAC"
        self._write_audit(user, op, full_path, True, reason)
        return True, reason

    def _write_audit(self, user: str, op: str, path: str, allowed: bool, reason: str) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "op": op,
            "path": path,
            "allowed": allowed,
            "reason": reason,
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")