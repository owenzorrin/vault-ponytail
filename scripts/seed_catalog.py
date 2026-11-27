"""Seed src/data/vault-errors.json from real HashiCorp error strings.

Usage:
  git clone --depth 1 https://github.com/hashicorp/vault        $SRC/vault-src
  git clone --depth 1 https://github.com/hashicorp/raft         $SRC/raft-src
  git clone --depth 1 https://github.com/hashicorp/go-kms-wrapping $SRC/kms-src
  git clone --depth 1 https://github.com/hashicorp/vault-plugin-auth-kubernetes $SRC/k8s-src
  git clone --depth 1 https://github.com/hashicorp/cap          $SRC/cap-src
  git clone --depth 1 https://github.com/hashicorp/go-plugin    $SRC/plugin-src
  SRC=$SRC python3 scripts/seed_catalog.py

Every entry's `probe` literal must exist in a non-test .go file of one of the
clones; its location is recorded in `source` and added to `references`.
The JSON is the source of truth afterwards: edit it directly (see README).
"""
import json, subprocess, re, os
H = os.path.expanduser(os.environ.get("SRC", "~"))
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "data", "vault-errors.json")
REPOS = {  # local clone -> (github slug, branch)
  f"{H}/vault-src": ("hashicorp/vault", "main"),
  f"{H}/raft-src": ("hashicorp/raft", "main"),
  f"{H}/kms-src": ("hashicorp/go-kms-wrapping", "main"),
  f"{H}/k8s-src": ("hashicorp/vault-plugin-auth-kubernetes", "main"),
  f"{H}/cap-src": ("hashicorp/cap", "main"),
  f"{H}/plugin-src": ("hashicorp/go-plugin", "main"),
}
D = "https://developer.hashicorp.com/vault"
def ref(t, u): return {"title": t, "url": u}
R_STATUS = ref("vault status command", f"{D}/docs/commands/status")
R_HEALTH = ref("sys/health API", f"{D}/api-docs/system/health")
R_SEAL = ref("Seal/Unseal concepts", f"{D}/docs/concepts/seal")
R_UNSEAL = ref("vault operator unseal", f"{D}/docs/commands/operator/unseal")
R_DIAG = ref("vault operator diagnose", f"{D}/docs/commands/operator/diagnose")
R_RAFT = ref("Integrated storage (raft) configuration", f"{D}/docs/configuration/storage/raft")
R_RAFTCMD = ref("vault operator raft", f"{D}/docs/commands/operator/raft")
R_IS = ref("Integrated storage concepts", f"{D}/docs/internals/integrated-storage")
R_QUORUM = ref("Recover from lost quorum", f"{D}/tutorials/raft/raft-lost-quorum")
R_HA = ref("High availability mode", f"{D}/docs/concepts/ha")
R_TCP = ref("TCP listener configuration", f"{D}/docs/configuration/listener/tcp")
R_TOKENS = ref("Tokens", f"{D}/docs/concepts/tokens")
R_LEASE = ref("Lease, renew, and revoke", f"{D}/docs/concepts/lease")
R_POLICY = ref("Policies", f"{D}/docs/concepts/policies")
R_AUDIT = ref("Audit devices", f"{D}/docs/audit")
R_REPL = ref("Vault Enterprise replication", f"{D}/docs/enterprise/replication")
R_PKI = ref("PKI secrets engine", f"{D}/docs/secrets/pki")
R_TRANSIT = ref("Transit secrets engine", f"{D}/docs/secrets/transit")
R_IDENT = ref("Identity secrets engine", f"{D}/docs/secrets/identity")
R_QUOTA = ref("Resource quotas", f"{D}/docs/concepts/resource-quotas")
R_MIGR = ref("Seal migration", f"{D}/docs/concepts/seal#seal-migration")
R_PLUGIN = ref("Plugin architecture", f"{D}/docs/plugins/plugin-architecture")
R_CONFIG = ref("Server configuration", f"{D}/docs/configuration")
def RS(name, title): return ref(f"{title} storage backend", f"{D}/docs/configuration/storage/{name}")
def RSEAL(name, title): return ref(f"{title} seal configuration", f"{D}/docs/configuration/seal/{name}")
def RAUTH(name, title): return ref(f"{title} auth method", f"{D}/docs/auth/{name}")

def s(step, command=None):
  d = {"step": step}
  if command: d["command"] = command
  return d
STATUS = s("Check seal, HA and storage state of this node", "vault status")
HEALTH = s("Query the health endpoint on every node (200 active, 429 standby, 473 perf standby, 501 uninitialized, 503 sealed)", "curl -s $VAULT_ADDR/v1/sys/health | jq")
PEERS = s("List raft peers; confirm one leader and that all voters are present", "vault operator raft list-peers")
AUTOPILOT = s("Check autopilot health, last contact and log index of each server", "vault operator raft autopilot state")
MONITOR = s("Stream server logs at debug level without a restart", "vault monitor -log-level=debug")
DIAG = s("Run offline checks of config, listener TLS, storage and seal", "vault operator diagnose -config=/etc/vault.d/vault.hcl")
UNSEAL = s("Submit unseal key shares until the threshold is reached", "vault operator unseal")
AUDITQ = s("Find the failing request in the audit log", "jq -c 'select(.error != null) | {time, type, path: .request.path, error}' /var/log/vault/audit.log | tail -20")
SEALSTAT = s("Check seal type, recovery mode and unseal progress", "curl -s $VAULT_ADDR/v1/sys/seal-status | jq")
PORTS = s("Verify API (8200) and cluster (8201) ports are reachable between every pair of nodes", "nc -zv <peer-host> 8200 && nc -zv <peer-host> 8201")
JOURNAL = s("Collect the full server log around the event", "journalctl -u vault --since '-30 min' --no-pager")
CONFIGCHK = s("Review the seal / storage / listener stanzas in the server config", "cat /etc/vault.d/vault.hcl")
AWSID = s("From the Vault host, confirm which IAM identity Vault is using", "aws sts get-caller-identity")
TOKLOOK = s("Inspect the token: policies, TTL, entity, namespace", "vault token lookup")
CAPS = s("Check the token's capabilities on the exact path", "vault token capabilities <path>")

E = []
def add(id, title, subsystem, location, patterns, summary, internal, external, steps, refs, examples, probe=None, origin=None):
  E.append(dict(id=id, title=title, subsystem=subsystem, location=location, patterns=patterns, summary=summary,
    internal_causes=internal, external_causes=external, troubleshooting_steps=steps, references=refs,
    examples=examples, _probe=probe if probe is not None else None, _origin=origin))

# ---------------- SEAL ----------------
add("seal-vault-sealed", "Vault is sealed", "seal", "both",
  [r"\bvault is sealed\b", r"core is sealed", r"raft storage is sealed", r"Code: 503.*sealed"],
  "The node is sealed: the barrier key is not in memory, so every request except status/unseal is rejected with HTTP 503.",
  ["Node was restarted or crashed and nobody unsealed it (Shamir seal).", "An operator or automation ran `vault operator seal`.", "Vault sealed itself after an unrecoverable internal error (look for the preceding ERROR line)."],
  ["Auto-unseal KMS/HSM was unreachable at startup, so the node never unsealed.", "Load balancer health check is routing traffic to a sealed node."],
  [STATUS, SEALSTAT, s("Scroll back in the log to the first ERROR before the seal; that line is the real cause"), UNSEAL, s("For auto-unseal, verify the KMS/HSM is reachable from this host and restart Vault", "systemctl restart vault"), HEALTH],
  [R_SEAL, R_UNSEAL, R_STATUS], ["Error making API request.\n\nURL: GET https://vault:8200/v1/secret/data/app\nCode: 503. Errors:\n\n* Vault is sealed"],
  probe="Vault is sealed")
add("seal-not-initialized", "Vault is not initialized", "seal", "internal",
  [r"vault is not initialized", r"server is not yet initialized", r"Code: 501"],
  "Storage contains no barrier/keyring, so Vault has never been initialized against this storage backend (or is pointed at the wrong one).",
  ["Brand-new cluster that has not run `vault operator init`.", "Raft follower that has not joined the cluster yet.", "Config `path`/`storage` stanza changed and now points at an empty location."],
  ["Storage backend data was deleted or restored from an empty backup.", "Wrong Consul/S3/DB prefix, bucket or table."],
  [STATUS, CONFIGCHK, s("If this is a raft follower, join it instead of initializing", "vault operator raft join https://<leader>:8200"), s("Only for a truly new cluster: initialize", "vault operator init")],
  [ref("vault operator init", f"{D}/docs/commands/operator/init"), R_HEALTH], ["Error making API request.\n\nCode: 400. Errors:\n\n* Vault is not initialized"],
  probe="Vault is not initialized")
add("seal-unseal-invalid-key", "Unseal failed, invalid key", "seal", "internal",
  [r"unseal failed,? invalid key", r"invalid key"],
  "The combined unseal key shares did not decrypt the barrier keyring.",
  ["Key shares come from a different cluster or a previous `vault operator init`.", "Shares from a pre-rekey set were mixed with the current ones.", "Shares were mistyped or base64/hex mixed."],
  ["Storage was restored from a backup taken after a rekey, so it expects different keys."],
  [SEALSTAT, s("Reset unseal progress and start again with shares from a single key set", "vault operator unseal -reset"), UNSEAL, s("Confirm with the key custodians which init/rekey generation the shares belong to")],
  [R_UNSEAL, ref("vault operator rekey", f"{D}/docs/commands/operator/rekey")], ["Error unsealing: Error making API request.\n\nURL: PUT https://127.0.0.1:8200/v1/sys/unseal\nCode: 400. Errors:\n\n* Unseal failed, invalid key"],
  probe="Unseal failed, invalid key")
add("seal-wrapper-unreachable", "Auto-unseal seal wrapper unreachable", "seal", "external",
  [r"seal wrapper may be unreachable", r"fetching stored unseal keys failed\"?\s*$", r"failed to (encrypt|decrypt) test value", r"no healthy seals", r"seal is unhealthy", r"failed to decrypt health test value"],
  "Vault's periodic seal health check, or startup unseal, could not complete an encrypt/decrypt round trip with the auto-unseal KMS/HSM.",
  ["Seal stanza has the wrong key ID, region, endpoint or mount path."],
  ["KMS/HSM endpoint not reachable (DNS, proxy, firewall, VPC endpoint, private link).", "IAM/credentials for the seal expired or were changed.", "KMS key disabled, scheduled for deletion, or its key policy changed.", "KMS throttling or regional outage."],
  [STATUS, s("Check the seal stanza for key id, region and endpoint", "grep -A10 '^seal' /etc/vault.d/vault.hcl"), AWSID, s("AWS KMS: test the key from the Vault host using Vault's credentials", "aws kms describe-key --key-id <kms_key_id> --region <region>"), s("Confirm network reachability to the KMS endpoint", "curl -sv https://kms.<region>.amazonaws.com 2>&1 | head -20"), MONITOR],
  [R_SEAL, RSEAL("awskms", "AWS KMS"), R_DIAG], ["2024-05-01T10:00:00.000Z [WARN]  core: seal health check failed: error=\"failed to encrypt test value, seal wrapper may be unreachable: context deadline exceeded\""],
  probe="seal wrapper may be unreachable")
add("seal-awskms", "AWS KMS auto-unseal error", "seal", "external",
  [r"error initializing AWS KMS wrapping client", r"error fetching AWS KMS wrapping key information", r"key id not found in env or config for aws kms wrapper", r"AccessDeniedException", r"KMSInvalidStateException", r"(NotFoundException|DisabledException).*(kms|key)", r"kms.*(NoCredentialProviders|ExpiredToken)"],
  "Vault could not use the AWS KMS key configured in `seal \"awskms\"`.",
  ["`kms_key_id`, `region` or `endpoint` is wrong in the seal stanza."],
  ["IAM role/instance profile lacks kms:Encrypt, kms:Decrypt or kms:DescribeKey.", "KMS key policy does not trust Vault's IAM principal.", "Key is disabled or pending deletion (KMSInvalidStateException).", "No route to KMS (missing VPC endpoint, proxy, SCP or firewall)."],
  [AWSID, s("Describe the key and check KeyState is Enabled", "aws kms describe-key --key-id <kms_key_id> --region <region>"), s("Test encrypt with Vault's credentials", "aws kms encrypt --key-id <kms_key_id> --plaintext fileb://<(echo test) --region <region>"), s("Review the key policy for Vault's role", "aws kms get-key-policy --key-id <kms_key_id> --policy-name default --region <region>"), s("Check CloudTrail for denied kms:Decrypt / kms:Encrypt calls from Vault's role"), STATUS],
  [RSEAL("awskms", "AWS KMS")], ["[ERROR] core: failed to unseal: error=\"error fetching AWS KMS wrapping key information: AccessDeniedException: User: arn:aws:sts::123456789012:assumed-role/vault/i-0abc is not authorized to perform: kms:DescribeKey\""],
  probe="error fetching AWS KMS wrapping key information")
add("seal-azurekeyvault", "Azure Key Vault auto-unseal error", "seal", "external",
  [r"error initializing Azure Key Vault wrapper client", r"error fetching Azure Key Vault wrapper key information", r"failed to acquire managed identity credentials", r"failed to get client secret credentials", r"failed to create keyvault client"],
  "Vault could not authenticate to, or read the key from, Azure Key Vault for auto-unseal.",
  ["`vault_name`, `key_name`, `tenant_id` or `environment` wrong in the seal stanza."],
  ["Managed identity not assigned to the VM/pod, or client secret expired.", "Key Vault access policy / RBAC lacks get, wrapKey and unwrapKey.", "Key Vault firewall or private endpoint blocks the Vault host."],
  [s("Confirm the identity can read the key", "az keyvault key show --vault-name <vault_name> --name <key_name>"), s("Check access policies / role assignments for wrapKey and unwrapKey", "az keyvault show --name <vault_name> --query properties.accessPolicies"), s("Check the Key Vault network rules", "az keyvault network-rule list --name <vault_name>"), STATUS],
  [RSEAL("azurekeyvault", "Azure Key Vault")], ["[ERROR] core: failed to unseal: error=\"error fetching Azure Key Vault wrapper key information: keyvault.BaseClient#GetKey: Failure responding to request: StatusCode=403\""],
  probe="error fetching Azure Key Vault wrapper key information")
add("seal-gcpckms", "GCP Cloud KMS auto-unseal error", "seal", "external",
  [r"error initializing GCP CKMS wrapper client", r"'(crypto_key|key_ring|project|region)' not found for GCP CKMS wrapper configuration", r"cloudkms.*(PermissionDenied|Permission .* denied)"],
  "Vault could not reach or use the Google Cloud KMS key configured in `seal \"gcpckms\"`.",
  ["`project`, `region`, `key_ring` or `crypto_key` missing or wrong in the seal stanza."],
  ["Service account lacks roles/cloudkms.cryptoKeyEncrypterDecrypter on the key.", "GOOGLE_APPLICATION_CREDENTIALS not readable by the vault user.", "Key version disabled or destroyed."],
  [s("Describe the crypto key and check the primary version state", "gcloud kms keys describe <crypto_key> --keyring <key_ring> --location <region> --project <project>"), s("Check IAM bindings on the key", "gcloud kms keys get-iam-policy <crypto_key> --keyring <key_ring> --location <region>"), STATUS],
  [RSEAL("gcpckms", "GCP Cloud KMS")], ["Error parsing Seal configuration: 'crypto_key' not found for GCP CKMS wrapper configuration"],
  probe="error initializing GCP CKMS wrapper client")
add("seal-transit", "Transit auto-unseal error", "seal", "external",
  [r"after (en|de)crypt operation .*(returned from vault|returned secret from vault)", r"transit seal configuration is invalid", r"(transit|seal).*Code: 403.*permission denied", r"error (en|de)crypting data: Error making API request"],
  "Vault could not use the remote Vault Transit key that unseals this cluster.",
  ["`address`, `mount_path` or `key_name` wrong in the seal stanza."],
  ["The transit cluster is sealed, down or unreachable.", "The seal token expired or was revoked (it must be a periodic or long-lived token).", "Token policy lacks update on transit/encrypt/<key> and transit/decrypt/<key>.", "TLS CA/client cert for the transit cluster is invalid."],
  [s("Check the transit (unsealer) cluster health", "VAULT_ADDR=<transit-addr> vault status"), s("Check the seal token TTL and policies on the transit cluster", "VAULT_ADDR=<transit-addr> VAULT_TOKEN=<seal-token> vault token lookup"), s("Confirm the key exists", "VAULT_ADDR=<transit-addr> vault read transit/keys/<key_name>"), STATUS],
  [RSEAL("transit", "Transit")], ["[ERROR] core: failed to unseal: error=\"error decrypting data: Error making API request.\n\nURL: PUT https://transit-vault:8200/v1/transit/decrypt/autounseal\nCode: 403. Errors:\n\n* permission denied\""],
  probe="after decrypt operation the returned secret from vault is nil")
add("seal-hsm-pkcs11", "HSM (PKCS#11) seal error", "seal", "external",
  [r"\bCKR_[A-Z_]+\b", r"pkcs11", r"error initializing (pkcs11|HSM)"],
  "The Enterprise PKCS#11 seal received an error from the HSM library (CKR_* return codes come from the HSM).",
  ["Wrong `lib`, `slot`/`token_label`, `pin`, `key_label` or mechanism in the seal stanza."],
  ["HSM unreachable or partition offline (network HSM).", "HSM client software version mismatch or session limit reached.", "PIN locked/expired (CKR_PIN_INCORRECT, CKR_PIN_LOCKED).", "Key not found in the partition (CKR_KEY_HANDLE_INVALID / CKR_OBJECT_HANDLE_INVALID)."],
  [s("List slots/tokens visible to the Vault host", "pkcs11-tool --module <lib.so> --list-slots"), s("Log in and list objects with the configured PIN", "pkcs11-tool --module <lib.so> --login --list-objects"), s("Check the HSM vendor client logs and connectivity"), STATUS],
  [RSEAL("pkcs11", "PKCS#11 HSM")], ["[ERROR] core: failed to unseal: error=\"error decrypting data: pkcs11: 0x30: CKR_DEVICE_ERROR\""],
  probe="", origin="HSM PKCS#11 return codes (Vault Enterprise HSM seal)")
add("seal-migration-required", "Seal migration required / pending", "seal", "internal",
  [r"requires seal migration", r"migrate option not provided and seal migration is pending", r"no migration seal found", r"cannot seal migrate from", r"no disabled seal in configuration", r"cannot auto-unseal during seal migration", r"cannot run in recovery mode when a seal migration is needed"],
  "The seal in the config differs from the seal that protects the data in storage, and Vault will not switch until a seal migration is run.",
  ["Seal stanza changed (Shamir to auto-unseal, auto-unseal to Shamir, or KMS to KMS) without `disabled = \"true\"` on the old seal.", "Not every node got the same config change.", "Migration started but was not finished on all nodes."],
  [],
  [CONFIGCHK, SEALSTAT, s("Keep the old seal in the config with disabled = \"true\" next to the new seal, then restart Vault"), s("Unseal with -migrate on each node (standbys first, then the active node)", "vault operator unseal -migrate"), STATUS],
  [R_MIGR], ["[WARN]  core: migrate option not provided and seal migration is pending"],
  probe="migrate option not provided and seal migration is pending")
add("seal-keys-unreadable", "Neither old nor new seal can read stored keys", "seal", "both",
  [r"neither the old nor new seal can read stored keys", r"decrypt error, neither the old nor new seal"],
  "During seal migration Vault tried both seals and neither could decrypt the stored keys.",
  ["Both seal stanzas point at the wrong keys.", "Storage was restored from a different cluster."],
  ["The old KMS key was deleted or disabled before migration finished.", "Credentials for either KMS are invalid."],
  [CONFIGCHK, s("Verify both KMS keys are enabled and accessible with Vault's credentials"), SEALSTAT, MONITOR],
  [R_MIGR], ["Error unsealing: neither the old nor new seal can read stored keys: old seal err=AccessDeniedException, new seal err=<nil>"],
  probe="neither the old nor new seal can read stored keys")
add("seal-generation-mismatch", "Newer seal generation found in storage", "seal", "internal",
  [r"newer seal generation (was )?found in storage", r"seal configuration in this node should be updated to match"],
  "Another node changed the seal configuration (multi-seal / seal HA) and this node's config is out of date.",
  ["Seal stanzas differ between nodes after a seal config change."],
  [],
  [s("Diff the seal stanzas across all nodes", "grep -A15 '^seal' /etc/vault.d/vault.hcl"), s("Copy the config from the previous active node, then restart this node", "systemctl restart vault"), STATUS],
  [R_SEAL], ["[ERROR] core: A newer seal generation was found in storage. The seal configuration in this node should be updated to match that of the previous active node, and this node should be restarted."],
  probe="newer seal generation found in storage")
add("seal-decrypt-failed", "Seal decrypt failed", "seal", "both",
  [r"error decrypting using seal", r"failed to decrypt envelope", r"error decrypting data encryption key", r"value has no key-id in common with currently healthy seals"],
  "A seal-wrapped value could not be decrypted with the configured seal key(s).",
  ["Seal config points to a different key than the one that wrapped the data."],
  ["KMS key was rotated with old versions disabled, or the key was replaced.", "KMS denied decrypt (IAM/key policy) or the KMS is unreachable."],
  [CONFIGCHK, s("Check KMS audit logs (CloudTrail / Azure Monitor / Cloud Audit Logs) for failed Decrypt calls"), STATUS, MONITOR],
  [R_SEAL], ["[ERROR] core: error decrypting using seal awskms: failed to decrypt envelope: cipher: message authentication failed"],
  probe="error decrypting using seal")
add("seal-config-missing", "Barrier initialized but seal configuration missing", "seal", "both",
  [r"barrier reports initialized but no seal configuration found", r"Recovery seal configuration not found for existing seal", r"failed to obtain seal/recovery configuration"],
  "Storage has a keyring but the seal/recovery configuration entries are missing or unreadable.",
  ["Partial restore or manual edits of core/ storage paths."],
  ["Storage backend returned partial data (eventual consistency, wrong prefix).", "Backup restore missing core/seal-config or core/recovery-config."],
  [DIAG, CONFIGCHK, s("Contact HashiCorp support before changing storage; collect a storage listing of core/")],
  [R_SEAL], ["[ERROR] core: barrier reports initialized but no seal configuration found"],
  probe="barrier reports initialized but no seal configuration found")
add("seal-standby-cannot-seal", "Cannot seal a standby node", "seal", "internal",
  [r"vault cannot seal when in standby mode"],
  "`vault operator seal` was sent to a standby. Only the active node can be sealed through the API.",
  ["Request reached a standby node directly or through a load balancer."], [],
  [STATUS, s("Send the seal request to the active node, or restart/stop the standby instead", "systemctl stop vault")],
  [R_HA], ["Error sealing: Error making API request.\n\nCode: 500. Errors:\n\n* vault cannot seal when in standby mode; please restart instead"],
  probe="vault cannot seal when in standby mode")
add("seal-mlock", "Failed to lock memory (mlock)", "seal", "external",
  [r"failed to lock memory", r"mlock syscall is not available"],
  "Vault could not mlock its memory at startup, so it refuses to start rather than risk swapping secrets to disk.",
  ["`disable_mlock` not set where mlock is unsupported."],
  ["Missing IPC_LOCK capability (containers) or CAP_IPC_LOCK on the binary.", "LimitMEMLOCK too low in the systemd unit."],
  [s("Grant the capability to the binary", "sudo setcap cap_ipc_lock=+ep $(readlink -f $(which vault))"), s("Check the systemd unit for LimitMEMLOCK=infinity and AmbientCapabilities=CAP_IPC_LOCK", "systemctl cat vault"), s("With integrated storage, HashiCorp recommends disable_mlock = true")],
  [ref("disable_mlock parameter", f"{D}/docs/configuration#disable_mlock")], ["Error initializing core: Failed to lock memory: cannot allocate memory\n\nThis usually means that the mlock syscall is not available."],
  probe="Failed to lock memory")

# ---------------- RAFT ----------------
add("raft-heartbeat-election", "Raft heartbeat timeout and election", "raft", "both",
  [r"heartbeat timeout reached, starting election", r"election timeout reached, restarting election", r"entering candidate state", r"pre-vote campaign failed"],
  "A follower stopped hearing from the leader and started an election. Occasional elections are normal; repeated ones mean the cluster is unstable.",
  ["Leader overloaded (large snapshots, heavy write load, GC pauses).", "Mismatched `performance_multiplier` across nodes."],
  ["Network latency, packet loss or partition on port 8201.", "Slow disk (fsync latency) on the leader or follower.", "VM CPU steal or noisy neighbors."],
  [PEERS, AUTOPILOT, PORTS, s("Check disk latency on the raft data volume", "iostat -x 1 5"), s("Check vault.raft metrics (commitTime, leader.lastContact)", "curl -s -H \"X-Vault-Token: $VAULT_TOKEN\" $VAULT_ADDR/v1/sys/metrics | jq '.Gauges[] | select(.Name|test(\"raft\"))'"), MONITOR],
  [R_RAFT, R_IS], ["2024-05-01T10:00:00.000Z [WARN]  storage.raft: heartbeat timeout reached, starting election: last-leader-addr=10.0.0.11:8201 last-leader-id=vault-1"],
  probe="heartbeat timeout reached, starting election")
add("raft-lost-quorum", "Raft lost quorum", "raft", "both",
  [r"failed to contact quorum of nodes", r"no known peers, aborting election", r"leadership lost while committing log", r"not part of (a )?stable configuration, aborting election" ],
  "The leader could not reach a majority of voters and stepped down, or no node can win an election. Writes stop until quorum returns.",
  ["Too many voters removed or failed (for example 2 of 3).", "Nodes removed from the configuration but still running."],
  ["Network partition between availability zones or a firewall change on port 8201.", "Hosts down, disks full, or pods rescheduled with lost volumes."],
  [PEERS, HEALTH, PORTS, s("Check disk space on the raft data directory", "df -h /opt/vault/data"), s("If quorum cannot come back, follow the lost-quorum procedure with peers.json")],
  [R_QUORUM, R_RAFT], ["[WARN]  storage.raft: failed to contact quorum of nodes, stepping down"],
  probe="failed to contact quorum of nodes, stepping down")
add("raft-rpc-failures", "Raft replication/heartbeat RPC failures", "raft", "external",
  [r"failed to appendEntries to", r"failed to heartbeat to", r"failed to pipeline appendEntries", r"failed to make requestVote RPC", r"raft.*(dial tcp|i/o timeout|connection refused|connection reset)"],
  "The raft leader cannot send log entries or heartbeats to a peer over the cluster port.",
  ["`cluster_addr` advertises an address other nodes cannot reach (NAT, 0.0.0.0, container IP)."],
  ["Firewall or security group blocking 8201.", "Peer down or restarting.", "TLS interception or a proxy on the cluster port (raft uses mTLS that Vault manages)."],
  [PEERS, PORTS, s("Check cluster_addr / api_addr in the config of the failing peer", "grep -E 'cluster_addr|api_addr' /etc/vault.d/vault.hcl"), AUTOPILOT],
  [R_RAFT, R_HA], ["[ERROR] storage.raft: failed to appendEntries to: peer=\"{Voter vault-2 10.0.0.12:8201}\" error=\"dial tcp 10.0.0.12:8201: connect: connection refused\""],
  probe="failed to appendEntries to")
add("raft-rejecting-vote", "Raft rejecting vote requests", "raft", "internal",
  [r"rejecting (pre-)?vote request since (we have a leader|node is not in configuration|node is not a voter|our last (index|term) is greater)"],
  "A node that is not part of the current configuration, or is behind, keeps asking for votes. Usually a removed or rejoined node that still has old raft data.",
  ["Node removed with `remove-peer` but still running with old data.", "Node restored from an old disk/snapshot, so its term/index is behind.", "Duplicate node_id across nodes."],
  [],
  [PEERS, s("Check node_id in each node's raft stanza is unique", "grep node_id /etc/vault.d/vault.hcl"), s("A single 'since we have a leader' message during an election is normal; act only if it repeats"), s("If the node is not in the configuration and should be, rejoin it", "vault operator raft join https://<leader>:8200"), s("Only for a node that was removed with remove-peer or restored from an old disk: stop it, move its raft data dir aside, then rejoin")],
  [R_RAFTCMD], ["[WARN]  storage.raft: rejecting vote request since node is not in configuration: from=10.0.0.14:8201"],
  probe="rejecting vote request since node is not in configuration")
add("raft-join-failed", "Raft join failed", "raft", "both",
  [r"failed to (retry )?join raft cluster", r"error in retry_join stanza", r"must provide leader address or auto-join metadata", r"failed to create tls config to communicate with leader node", r"invalid retry_join config", r"too many concurrent raft retry joins"],
  "A node could not join the raft cluster through `retry_join` or `vault operator raft join`.",
  ["`leader_api_addr` wrong or uses http where the leader serves https.", "`leader_ca_cert_file` / `leader_tls_servername` do not match the leader's API certificate.", "Node already has raft data from another cluster."],
  ["Leader API port 8200 not reachable from the joining node.", "DNS for the leader address does not resolve."],
  [s("Test the leader API from the joining node", "curl -sv --cacert <leader_ca> https://<leader>:8200/v1/sys/health"), s("Review the retry_join stanza", "grep -A8 retry_join /etc/vault.d/vault.hcl"), PEERS, MONITOR],
  [R_RAFT, R_RAFTCMD], ["[ERROR] core: failed to retry join raft cluster: retry=2s err=\"failed to create tls config to communicate with leader node \\\"https://vault-0.vault-internal:8200\\\": open /vault/tls/ca.crt: no such file or directory\"", "Error joining the node to the Raft cluster: Error making API request.\n\nCode: 500. Errors:\n\n* failed to join raft cluster: context deadline exceeded"],
  probe="failed to retry join raft cluster")
add("raft-challenge", "Raft bootstrap challenge failed", "raft", "both",
  [r"failed to get raft challenge", r"error during raft bootstrap (init )?call", r"raft challenge is nil", r"too many raft challenges in flight", r"error decoding raft bootstrap challenge", r"failed to send answer to raft leader node", r"could not retrieve raft bootstrap package"],
  "During join the follower must decrypt a challenge from the leader using the shared seal. That exchange failed.",
  ["Follower is configured with a different seal or KMS key than the leader.", "Shamir follower was not unsealed with the cluster's unseal keys after join."],
  ["Follower cannot reach the leader's API address (load balancer, TLS SNI, firewall).", "Follower cannot reach the KMS to decrypt the challenge."],
  [s("Compare the seal stanza on leader and follower", "grep -A10 '^seal' /etc/vault.d/vault.hcl"), s("Test the leader API from the follower", "curl -sv https://<leader>:8200/v1/sys/health"), s("For Shamir seals, unseal the follower after it joins", "vault operator unseal"), STATUS],
  [R_RAFT], ["[ERROR] core: failed to retry join raft cluster: err=\"failed to get raft challenge: Error making API request.\n\nURL: POST https://vault-0:8200/v1/sys/storage/raft/bootstrap/challenge\nCode: 503\""],
  probe="failed to get raft challenge")
add("raft-join-seal-state", "Node seal state wrong for raft join", "raft", "internal",
  [r"node must be (sealed|unsealed) before joining", r"node must be unsealed to bootstrap", r"can't perform a seal migration while joining a raft cluster", r"incompatible seal types between raft leader"],
  "Raft join requires a specific seal state, or the follower's seal type differs from the leader's.",
  ["Joining a node that is already unsealed against other storage.", "Follower uses Shamir while the leader uses auto-unseal (or the reverse)."], [],
  [STATUS, CONFIGCHK, s("'must be unsealed': unseal the node, then retry the join", "vault operator unseal"), s("'must be sealed before joining': the node already unsealed against other storage; restart it with the raft storage stanza, then join"), s("'incompatible seal types': align the seal stanza with the leader, then restart and rejoin")],
  [R_RAFT], ["Error joining the node to the Raft cluster: Code: 500. Errors:\n\n* node must be sealed before joining"],
  probe="node must be sealed before joining")
add("raft-node-removed", "Raft node removed / stale data", "raft", "internal",
  [r"raft data for this node must be cleaned up before it can be added back", r"raft is already initialized", r"node has been removed from the HA cluster", r"existing raft\.db detected"],
  "The node's raft directory belongs to an old membership (it was removed), or the node was already initialized.",
  ["`vault operator raft remove-peer` was run, then the node was restarted with its old data.", "Re-using a volume from another cluster."], [],
  [PEERS, s("Stop Vault, move the raft data directory away, then start and rejoin", "sudo systemctl stop vault && sudo mv /opt/vault/data /opt/vault/data.bak && sudo systemctl start vault"), s("Rejoin the node", "vault operator raft join https://<leader>:8200")],
  [R_RAFTCMD], ["[ERROR] core: node has been removed from the HA cluster. Raft data for this node must be cleaned up before it can be added back"],
  probe="Raft data for this node must be cleaned up before it can be added back")
add("raft-snapshot-key-mismatch", "Raft snapshot from a different seal", "raft", "internal",
  [r"could not verify hash file, possibly the snapshot is using a different (autoseal key|set of unseal keys)", r"snapshot-force API to bypass"],
  "The snapshot was taken on a cluster with a different seal/unseal keys, so its integrity hash cannot be checked.",
  ["Restoring a snapshot from another cluster (DR test, migration) or from before a rekey."], [],
  [s("Confirm where the snapshot came from and which seal it was taken with"), s("If you intend to restore it, use force; the target then needs the source cluster's unseal/recovery keys", "vault operator raft snapshot restore -force backup.snap"), STATUS],
  [ref("vault operator raft snapshot", f"{D}/docs/commands/operator/raft#snapshot")], ["Error installing the snapshot: Code: 400. Errors:\n\n* could not verify hash file, possibly the snapshot is using a different set of unseal keys; use the snapshot-force API to bypass this check"],
  probe="could not verify hash file, possibly the snapshot is using a different set of unseal keys")
add("raft-snapshot-io", "Raft snapshot install / write failure", "raft", "external",
  [r"failed to (install|make|reap|scan) snapshot", r"failed to move snapshot into place", r"snapshot path not accessible", r"incomplete snapshot", r"raft snapshot restore failed", r"no snapshot data", r"unsupported snapshot version"],
  "Raft could not create, move or install a snapshot on local disk.",
  ["Corrupt or truncated snapshot file supplied to restore."],
  ["Disk full or slow on the raft data volume.", "Wrong ownership/permissions on the snapshots directory.", "Read-only filesystem or SELinux/AppArmor denial."],
  [s("Check free space and inodes", "df -h /opt/vault/data && df -i /opt/vault/data"), s("Check ownership of the raft directory", "ls -la /opt/vault/data /opt/vault/data/raft/snapshots"), s("Look for kernel or filesystem errors", "dmesg | tail -50"), PEERS],
  [R_RAFT], ["[ERROR] storage.raft: failed to install snapshot: error=\"failed to move snapshot into place: rename: no space left on device\""],
  probe="failed to move snapshot into place")
add("raft-peers-json-recovery", "Raft peers.json recovery failed", "raft", "internal",
  [r"raft recovery failed", r"recovering raft cluster failed", r"raft recovery failed to parse peers\.json"],
  "Vault found a `raft/peers.json` file at startup but could not use it for manual recovery.",
  ["Malformed JSON, wrong node IDs or addresses in peers.json.", "peers.json copied to only some nodes."], [],
  [s("Validate the file", "jq . /opt/vault/data/raft/peers.json"), s("Confirm each id matches the node_id and each address is the cluster address (host:8201)"), s("Place an identical peers.json on every surviving node, then restart them")],
  [R_QUORUM], ["[ERROR] core: raft recovery failed to parse peers.json: invalid character '}' looking for beginning of object key string"],
  probe="raft recovery failed to parse peers.json")
add("raft-max-entry-size", "Raft entry too large", "raft", "internal",
  [r"retrieved entry value is too large", r"max_entry_size", r"max_mount_and_namespace_table_entry_size", r"put failed due to value being too large"],
  "A storage entry exceeds raft `max_entry_size` (default 1 MiB), often the mount table or a large KV secret.",
  ["Very many mounts/namespaces make the mount table too large.", "Clients write very large KV values.", "max_entry_size was lowered after data was written."], [],
  [s("Check the configured limits in the raft stanza", "grep -E 'max_entry_size|max_mount' /etc/vault.d/vault.hcl"), s("Find the large writes in the audit log"), s("Raise max_entry_size on all nodes consistently, or reduce payload size")],
  [R_RAFT], ["[ERROR] core: retrieved entry value is too large, has raft's max_entry_size or max_mount_and_namespace_table_entry_size been reduced?"],
  probe="retrieved entry value is too large")
add("raft-fsm-permissions", "Raft FSM / data file problems", "raft", "external",
  [r"raft FSM db file has wider permissions than needed", r"error checking raft FSM db file", r"failed to check if raft\.db already exists", r"MAP_POPULATE mmap flag has not been set"],
  "Vault found unexpected permissions, size or access problems on the raft vault.db / raft.db files.",
  [],
  ["Data files owned by root or world-readable after manual copy/restore.", "Database larger than available memory (slow startup)."],
  [s("Check file modes and owner", "ls -la /opt/vault/data /opt/vault/data/raft"), s("Fix ownership and modes", "sudo chown -R vault:vault /opt/vault/data && sudo chmod 600 /opt/vault/data/vault.db"), s("Check memory against database size", "free -h && du -sh /opt/vault/data")],
  [R_RAFT], ["[WARN]  storage.raft.fsm: raft FSM db file has wider permissions than needed: needed=-rw------- existing=-rw-r--r--"],
  probe="raft FSM db file has wider permissions than needed")
add("raft-not-ready", "Raft storage not initialized / shut down", "raft", "internal",
  [r"raft storage is not initialized", r"raft storage is not in use", r"raft backend (is )?not in use", r"raft is shutdown", r"raft storage autopilot is not initialized", r"could not check raft state"],
  "A raft operation was called while raft is not running on this node, or the cluster uses a different storage backend.",
  ["Running `vault operator raft` commands against a Consul-backed cluster.", "Node is still starting, sealed or not yet joined."], [],
  [STATUS, s("Confirm storage type (Storage Type line)", "vault status | grep -i storage"), PEERS],
  [R_RAFTCMD], ["Error reading the raft cluster configuration: Code: 500. Errors:\n\n* raft storage is not initialized"],
  probe="raft storage is not initialized")
add("raft-unspecified-ip", "Raft cluster_addr is unspecified", "raft", "internal",
  [r"cannot use unspecified IP with raft storage", r"no raft addr found"],
  "`cluster_addr` resolves to 0.0.0.0 or `::`, which peers cannot dial.",
  ["cluster_addr set to 0.0.0.0, or derived from a listener bound to all interfaces."], [],
  [s("Set cluster_addr to a routable address on every node", "grep cluster_addr /etc/vault.d/vault.hcl"), s("Restart and verify", "vault operator raft list-peers")],
  [R_RAFT, ref("cluster_addr parameter", f"{D}/docs/configuration#cluster_addr")], ["Error initializing storage of type raft: cannot use unspecified IP with raft storage: 0.0.0.0:8201"],
  probe="cannot use unspecified IP with raft storage")
add("raft-tls-keyring", "Raft TLS keyring problems", "raft", "internal",
  [r"could not find raft TLS configuration", r"could not decode raft TLS configuration", r"failed to read raft TLS keyring", r"no active raft TLS key found", r"got raft connection but no local cert", r"raft tls periodic upgrade check failed"],
  "Vault manages its own mTLS keyring for raft cluster traffic, and it could not load or rotate it.",
  ["Node not fully unsealed when raft traffic arrived.", "Keyring storage entry damaged after partial restore."], [],
  [STATUS, PEERS, MONITOR],
  [R_IS], ["[ERROR] storage.raft: no active raft TLS key found"],
  probe="no active raft TLS key found")
add("raft-autojoin-discovery", "Raft cloud auto-join discovery failed", "raft", "external",
  [r"failed to create auto-join discovery", r"failed to parse addresses from auto-join metadata", r"auto_join.*(AccessDenied|UnauthorizedOperation|not authorized)"],
  "`retry_join { auto_join = \"provider=...\" }` could not list peers through the cloud provider API.",
  ["Malformed auto_join string (provider, tag_key, tag_value, region)."],
  ["IAM role lacks ec2:DescribeInstances (AWS) or the equivalent on Azure/GCP.", "Instances do not carry the expected tags.", "No route to the cloud metadata or API endpoint."],
  [s("Review the auto_join string", "grep auto_join /etc/vault.d/vault.hcl"), AWSID, s("Confirm instances are discoverable by tag", "aws ec2 describe-instances --filters Name=tag:<tag_key>,Values=<tag_value> --query 'Reservations[].Instances[].PrivateIpAddress'")],
  [R_RAFT], ["[ERROR] core: failed to retry join raft cluster: error=\"failed to parse addresses from auto-join metadata: discover-aws: DescribeInstances failed: UnauthorizedOperation\""],
  probe="failed to parse addresses from auto-join metadata")

# ---------------- STORAGE ----------------
add("storage-consul-lock-lost", "Consul session / HA lock lost", "storage", "external",
  [r"failed to renew consul session for more than the TTL, lock lost", r"session check failed on write, we lost active node lock", r"consul.*(lock lost|session invalidated)"],
  "The active node lost its Consul lock, stepped down, and a standby took over (leadership flapping if repeated).",
  ["`session_ttl` / `lock_wait_time` too aggressive for the environment."],
  ["Consul agent on the Vault host unhealthy or restarting.", "Consul servers lost leader or are overloaded.", "Network latency between Vault, the agent and the Consul servers."],
  [s("Check the local Consul agent and cluster members", "consul members"), s("Check Consul raft health", "consul operator raft list-peers"), s("Look for session invalidations in the Consul agent logs", "journalctl -u consul --since '-30 min' | grep -i session"), STATUS],
  [RS("consul", "Consul")], ["[WARN]  storage.consul: session check failed on write, we lost active node lock, stepping down"],
  probe="session check failed on write, we lost active node lock")
add("storage-consul-access", "Consul storage access/ACL error", "storage", "external",
  [r"Unexpected response code: 403", r"ACL not found", r"rpc error making call: Permission denied", r"key or cert path: .* cannot be loaded from consul config file", r"storage\.consul.*(connection refused|i/o timeout|no such host)", r"invalid consistency_mode value"],
  "Vault could not read or write its Consul KV prefix.",
  ["Wrong `address`, `scheme`, `path` or TLS files in the consul storage stanza."],
  ["Consul ACL token missing, expired or lacking key_prefix/session write.", "Consul agent not listening on the configured address.", "Consul TLS/mTLS required but not configured."],
  [s("Test the token against Consul directly", "CONSUL_HTTP_TOKEN=<token> consul kv get -recurse vault/ | head"), s("Inspect the ACL token's policies", "consul acl token read -self"), s("Confirm agent reachability", "curl -sv http://127.0.0.1:8500/v1/status/leader")],
  [RS("consul", "Consul")], ["[ERROR] core: failed to check for initialization: error=\"Unexpected response code: 403 (ACL not found)\""],
  probe="cannot be loaded from consul config file")
add("storage-etcd", "etcd storage error", "storage", "external",
  [r"failed to discover etcd endpoints through SRV discovery", r"etcd: unknown API version", r"etcdserver: (request timed out|mvcc: database space exceeded|leader changed|no leader)", r"storage\.etcd.*context deadline exceeded"],
  "Vault's etcd backend could not reach etcd, or etcd rejected the request.",
  ["Wrong `address` / `etcd_api` / TLS settings in the storage stanza."],
  ["etcd quota exceeded (needs compaction and defrag).", "etcd cluster lost leader or is slow (disk fsync).", "Network or TLS problems to the etcd endpoints."],
  [s("Check etcd endpoint health", "etcdctl --endpoints=<endpoints> endpoint health"), s("Check status, DB size and alarms", "etcdctl --endpoints=<endpoints> endpoint status -w table && etcdctl alarm list")],
  [RS("etcd", "etcd")], ["[ERROR] core: error=\"etcdserver: mvcc: database space exceeded\""],
  probe="failed to discover etcd endpoints through SRV discovery")
add("storage-dynamodb", "DynamoDB storage error", "storage", "external",
  [r"ProvisionedThroughputExceededException", r"dynamodb: timeout handling UnproccessedItems", r"Could not establish AWS configuration", r"ResourceNotFoundException.*(table|Table)", r"dynamodb.*AccessDeniedException", r"error renewing leadership lock"],
  "Vault's DynamoDB backend was throttled, denied, or could not find its table.",
  ["Wrong `table`, `region` or `endpoint`; ha_enabled without suitable settings."],
  ["Table capacity too low (provisioned mode) causing throttling.", "IAM policy missing dynamodb:GetItem/PutItem/DeleteItem/Query/DescribeTable on the table.", "Credentials not available (no instance profile / env)."],
  [AWSID, s("Describe the table and capacity", "aws dynamodb describe-table --table-name <table> --region <region>"), s("Check ThrottledRequests and ConsumedWriteCapacity metrics in CloudWatch for the table")],
  [RS("dynamodb", "DynamoDB")], ["[ERROR] core: error=\"ProvisionedThroughputExceededException: The level of configured provisioned throughput for the table was exceeded\""],
  probe="dynamodb: timeout handling UnproccessedItems")
add("storage-s3", "S3 storage error", "storage", "external",
  [r"unable to access bucket .* in region", r"'bucket' must be set", r"NoSuchBucket", r"got nil response from S3", r"s3.*AccessDenied"],
  "Vault could not access the configured S3 bucket.",
  ["Wrong `bucket`, `region` or `endpoint` (S3-compatible stores).", "`s3_force_path_style` needed for MinIO-type endpoints."],
  ["IAM/bucket policy lacks s3:ListBucket, s3:GetObject, s3:PutObject, s3:DeleteObject.", "Bucket in another region, or blocked by VPC endpoint policy or SCP."],
  [AWSID, s("List the bucket with Vault's credentials", "aws s3 ls s3://<bucket>/ --region <region>"), s("Review the bucket policy", "aws s3api get-bucket-policy --bucket <bucket>")],
  [RS("s3", "S3")], ["Error initializing storage of type s3: unable to access bucket \"vault-data\" in region \"us-east-1\": AccessDenied: Access Denied"],
  probe="unable to access bucket")
add("storage-postgresql", "PostgreSQL storage error", "storage", "external",
  [r"failed to connect to postgres", r"missing connection_url", r"PG version doesn't support HA", r"pq: password authentication failed", r"pq: relation \"vault_[a-z_]+\" does not exist", r"pq: permission denied for (table|relation)"],
  "Vault's PostgreSQL backend could not connect, authenticate, or find its tables.",
  ["`connection_url`, `table` or `ha_table` wrong in the storage stanza."],
  ["DB credentials rotated or wrong.", "Tables vault_kv_store / vault_ha_locks not created (Vault does not create them).", "pg_hba.conf, network or TLS (sslmode) blocking the connection."],
  [s("Connect with the same URL from the Vault host", "psql '<connection_url>' -c '\\dt vault*'"), s("Create the required tables if missing (see the PostgreSQL storage docs)")],
  [RS("postgresql", "PostgreSQL")], ["Error initializing storage of type postgresql: failed to connect to postgres: pq: password authentication failed for user \"vault\""],
  probe="failed to connect to postgres")
add("storage-mysql", "MySQL storage error", "storage", "external",
  [r"failed to connect to mysql", r"mysql: (unable to update DB with new leader information|getting global lock id failed|lock already held)", r"Error 1045", r"Access denied for user", r"failed to (create|check) mysql (database|table)"],
  "Vault's MySQL backend could not connect, create its schema, or take the HA lock.",
  ["Wrong `address`, `database`, `table` or TLS (`tls_ca_file`) settings."],
  ["Invalid credentials or missing grants (CREATE, SELECT, INSERT, UPDATE, DELETE).", "Network or TLS problem to the MySQL server."],
  [s("Connect from the Vault host", "mysql -h <address> -u <username> -p -e 'SHOW GRANTS'"), CONFIGCHK],
  [RS("mysql", "MySQL")], ["Error initializing storage of type mysql: failed to connect to mysql: Error 1045: Access denied for user 'vault'@'10.0.0.5'"],
  probe="failed to connect to mysql")
add("storage-gcs", "Google Cloud Storage backend error", "storage", "external",
  [r"failed to create (HA )?storage client", r"missing bucket name", r"googleapi: Error 403", r"failed to (put data|read object|delete key)"],
  "Vault's GCS backend could not create a client or access the bucket.",
  ["Wrong bucket name or missing HA settings."],
  ["Service account lacks storage.objects.* on the bucket.", "Credentials file not readable by the vault user."],
  [s("List the bucket with Vault's identity", "gsutil ls gs://<bucket>"), s("Check bucket IAM", "gsutil iam get gs://<bucket>")],
  [RS("google-cloud-storage", "Google Cloud Storage")], ["Error initializing storage of type gcs: failed to create storage client: dialing: google: could not find default credentials"],
  probe="failed to create storage client")
add("storage-azure", "Azure storage backend error", "storage", "external",
  [r"failed to create Azure client", r"failed to (get properties for|create) .*container", r"couldn't refresh token credential", r"failed to obtain auth token from IMDS"],
  "Vault's Azure Blob storage backend could not authenticate or access the container.",
  ["Wrong accountName/container/environment in the storage stanza."],
  ["Managed identity not assigned or lacks Storage Blob Data Contributor.", "Storage account firewall blocks the Vault host.", "IMDS unreachable from the container."],
  [s("Check access with Vault's identity", "az storage container show --account-name <accountName> --name <container> --auth-mode login"), s("Check IMDS from the host", "curl -s -H Metadata:true 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'")],
  [RS("azure", "Azure")], ["Error initializing storage of type azure: failed to get properties for container \"vault\": StatusCode=403"],
  probe="failed to obtain auth token from IMDS")
add("storage-readonly", "Cannot write to read-only storage", "storage", "internal",
  [r"cannot write to readonly storage"],
  "A write reached a read-only storage view, for example on a performance secondary, a DR secondary or during recovery mode.",
  ["Writing to a replicated mount on a performance secondary that is not forwarded.", "Node in recovery mode."], [],
  [STATUS, s("Check replication mode of this cluster", "vault read -format=json sys/replication/status | jq '.data | {dr: .dr.mode, perf: .performance.mode}'"), s("Send the write to the primary, or mark the mount local if intended")],
  [R_REPL], ["Error writing data to secret/foo: Code: 500. Errors:\n\n* cannot write to readonly storage"],
  probe="cannot write to readonly storage")
add("storage-ha-lock", "HA lock acquisition failure", "storage", "both",
  [r"failed to acquire lock", r"lock already held", r"lock not held", r"error renewing leadership lock", r"attempt lock: "],
  "The node could not acquire or keep the HA lock in the storage/HA backend, so it stays standby or steps down.",
  ["Two clusters pointed at the same storage path.", "Clock skew affecting lock TTLs."],
  ["Storage/HA backend slow or unavailable (Consul, etcd, DynamoDB, ZooKeeper, DB).", "Network latency to the HA backend."],
  [STATUS, HEALTH, s("Check the HA backend health with its own tooling (consul members, etcdctl endpoint health, ...)"), MONITOR],
  [R_HA], ["[ERROR] core: failed to acquire lock: error=\"context deadline exceeded\""],
  probe="failed to acquire lock")
add("storage-latency-timeout", "Storage request timed out", "storage", "both",
  [r"(physical|storage)[^ ]*.*context deadline exceeded", r"failed to persist keyring: context deadline exceeded", r"error checking (health|initialization).*context deadline exceeded"],
  "A storage operation did not finish before its context deadline. Vault is waiting on the storage layer.",
  ["Very large lease counts or mount tables slow down startup/unseal.", "Raft leader overloaded."],
  ["Storage backend latency (disk fsync, network, throttling).", "Network partition to the backend."],
  [STATUS, s("Check storage latency metrics (vault.<backend>.get/put)", "curl -s -H \"X-Vault-Token: $VAULT_TOKEN\" $VAULT_ADDR/v1/sys/metrics | jq '.Samples[] | select(.Name|test(\"(raft-storage|consul|dynamodb|postgres).*(get|put)\"))'"), s("Check disk latency on raft nodes", "iostat -x 1 5"), MONITOR],
  [R_CONFIG], ["[ERROR] core: failed to persist keyring: context deadline exceeded"],
  probe="", origin="Go context deadline surfaced by the storage backend client")

# ---------------- TLS ----------------
add("tls-unknown-authority", "x509: certificate signed by unknown authority", "tls", "external",
  [r"x509: certificate signed by unknown authority", r"tls: failed to verify certificate"],
  "The client (CLI, agent, app, peer node or plugin) does not trust the CA that signed Vault's (or the remote service's) certificate.",
  ["`VAULT_CACERT` / `ca_cert` / `leader_ca_cert_file` not set."],
  ["Private CA not in the system trust store.", "TLS-intercepting proxy or load balancer presents its own certificate.", "Intermediate certificate missing from the server chain."],
  [s("Inspect the chain the server actually presents", "openssl s_client -connect <host>:8200 -showcerts </dev/null"), s("Point the client at the CA bundle", "export VAULT_CACERT=/etc/vault.d/ca.pem"), s("Verify the server cert against the CA", "openssl verify -CAfile ca.pem server.pem")],
  [R_TCP, ref("VAULT_CACERT environment variable", f"{D}/docs/commands#vault_cacert")], ["Error checking seal status: Get \"https://vault.example.com:8200/v1/sys/seal-status\": tls: failed to verify certificate: x509: certificate signed by unknown authority"],
  probe="", origin="Go crypto/x509 (client side)")
add("tls-hostname-mismatch", "x509: certificate name mismatch", "tls", "external",
  [r"x509: certificate is valid for .*, not ", r"doesn't contain any IP SANs", r"x509: certificate is not valid for any names"],
  "The certificate's SANs do not include the hostname or IP the client used.",
  ["`api_addr` / `leader_api_addr` / `leader_tls_servername` use a name not in the cert."],
  ["Certificate issued without the load balancer DNS name or node IPs.", "Client connects by IP while the cert has only DNS SANs."],
  [s("List SANs on the served certificate", "openssl s_client -connect <host>:8200 </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName"), s("Use a matching hostname, set VAULT_TLS_SERVER_NAME, or reissue the cert with the right SANs")],
  [R_TCP], ["Error making API request: Get \"https://10.0.0.11:8200/v1/sys/health\": x509: cannot validate certificate for 10.0.0.11 because it doesn't contain any IP SANs"],
  probe="", origin="Go crypto/x509 (client side)")
add("tls-cert-expired", "x509: certificate expired", "tls", "external",
  [r"x509: certificate has expired or is not yet valid", r"certificate has expired"],
  "A certificate in the chain is expired or not yet valid. Check the system clock too.",
  [],
  ["Listener cert or intermediate expired.", "System clock skew on client or server (NTP).", "Upstream service (KMS proxy, LDAP, DB) cert expired."],
  [s("Check validity dates", "openssl s_client -connect <host>:8200 </dev/null 2>/dev/null | openssl x509 -noout -dates"), s("Check clock sync", "timedatectl status"), s("Replace the cert and reload the listener without restart", "kill -HUP $(pidof vault)")],
  [R_TCP], ["[ERROR] core: error=\"x509: certificate has expired or is not yet valid: current time 2024-05-01T10:00:00Z is after 2024-04-30T00:00:00Z\""],
  probe="", origin="Go crypto/x509 (client side)")
add("tls-http-https-mismatch", "HTTP/HTTPS scheme mismatch", "tls", "external",
  [r"server gave HTTP response to HTTPS client", r"client sent an HTTP request to an HTTPS server"],
  "Client and server disagree on TLS: one side uses http:// and the other https://.",
  ["Listener has `tls_disable = true` while VAULT_ADDR uses https (or the reverse).", "`api_addr` / `leader_api_addr` uses the wrong scheme."],
  ["Load balancer terminates TLS and forwards plain HTTP (or the reverse)."],
  [s("Check VAULT_ADDR scheme", "echo $VAULT_ADDR"), s("Check the listener's tls_disable", "grep -A6 'listener' /etc/vault.d/vault.hcl"), s("Test both schemes", "curl -sv http://<host>:8200/v1/sys/health; curl -skv https://<host>:8200/v1/sys/health")],
  [R_TCP], ["Error checking seal status: Get \"https://127.0.0.1:8200/v1/sys/seal-status\": http: server gave HTTP response to HTTPS client"],
  probe="", origin="Go net/http")
add("tls-handshake", "TLS handshake failure", "tls", "both",
  [r"TLS handshake error from", r"remote error: tls: (bad certificate|unknown certificate authority|handshake failure|protocol version)", r"tls: handshake failure", r"tls: no cipher suite supported"],
  "A TLS handshake to the listener failed: client cert required, version/cipher mismatch, or an untrusted client.",
  ["`tls_require_and_verify_client_cert` enabled but clients send no cert.", "`tls_min_version` / `tls_cipher_suites` too strict for the clients."],
  ["Load balancer health checks over plain TCP/HTTP (noisy but harmless).", "Old client TLS stack."],
  [s("Identify the source IPs in the log lines (LB health checks are common)"), s("Test the handshake and negotiated protocol", "openssl s_client -connect <host>:8200 -tls1_2 </dev/null"), s("Review listener TLS options", "grep -E 'tls_' /etc/vault.d/vault.hcl")],
  [R_TCP], ["2024-05-01T10:00:00.000Z [INFO]  http: TLS handshake error from 10.0.1.5:51544: remote error: tls: bad certificate"],
  probe="", origin="Go crypto/tls / net/http server")
add("tls-listener-config", "Listener TLS configuration error", "tls", "internal",
  [r"error loading TLS cert", r"'tls_(min|max)_version' value .* not supported", r"'tls_max_version' must be greater than or equal to 'tls_min_version'", r"'tls_disable_client_certs' and 'tls_require_and_verify_client_cert' are mutually exclusive", r"failed to (read|parse CA certificate in) tls_client_ca_file", r"invalid value for '?tls_cipher_suites'?", r"tls: private key does not match public key"],
  "Vault could not build the listener TLS config from the files and options in the listener stanza.",
  ["Wrong tls_cert_file / tls_key_file paths, key/cert mismatch, or PEM order (leaf first, then intermediates).", "Invalid or conflicting tls_* options."],
  ["Files not readable by the vault user (permissions, SELinux)."],
  [s("Check that key and cert match", "c=$(openssl x509 -noout -pubkey -in vault.crt) && k=$(openssl pkey -pubout -in vault.key) && [ \"$c\" = \"$k\" ] && echo match || echo MISMATCH-or-unreadable"), s("Check file permissions for the vault user", "sudo -u vault cat /etc/vault.d/tls/vault.key >/dev/null && echo readable"), DIAG],
  [R_TCP], ["Error initializing listener of type tcp: error loading TLS cert: open /etc/vault.d/tls/vault.crt: permission denied"],
  probe="error loading TLS cert")

# ---------------- HA / FORWARDING ----------------
add("ha-active-not-found", "Active node not found", "ha", "both",
  [r"local node not active but active cluster node not found", r"Vault is not configured for highly-available mode", r"Code: 500.*active cluster node not found"],
  "A standby received a request but does not know which node is active, so it cannot forward.",
  ["Election in progress or leadership flapping.", "`api_addr` / `cluster_addr` advertise unreachable addresses."],
  ["HA/storage backend unhealthy, so no node holds the lock.", "Cluster port 8201 blocked between nodes."],
  [STATUS, HEALTH, PEERS, PORTS, s("Check which node holds leadership", "vault read sys/leader")],
  [R_HA], ["Error making API request.\n\nCode: 500. Errors:\n\n* local node not active but active cluster node not found"],
  probe="local node not active but active cluster node not found")
add("ha-forwarding-failed", "Standby request forwarding failed", "ha", "external",
  [r"error during forward(ed|ing) RPC request", r"forward request error", r"cannot forward request; no connection or address not known", r"error creating forwarding RPC request", r"err setting up forwarding rpc client", r"error parsing cluster address attempting to refresh forwarding connection"],
  "A standby could not forward a client request to the active node over the cluster port (gRPC on 8201).",
  ["`cluster_addr` of the active node is unreachable from standbys."],
  ["Firewall/security group blocks 8201.", "Load balancer or proxy in front of 8201 (it must be direct TCP).", "Active node changed and connections are being re-established."],
  [STATUS, s("Check leader and its cluster address", "vault read sys/leader"), PORTS, MONITOR],
  [R_HA], ["[ERROR] core: forward request error: error=\"error during forwarding RPC request\""],
  probe="error during forwarding RPC request")
add("ha-perf-standby-forward", "Please forward to the active node", "ha", "internal",
  [r"please forward to the active node"],
  "A performance standby got a write it cannot handle locally. Vault normally forwards this; if a client sees it, forwarding is broken or bypassed.",
  ["Client talks to a perf standby with forwarding disabled.", "Plugin returns the error directly."],
  [],
  [STATUS, s("Send writes to the active node through the load balancer (use sys/health?perfstandbyok for read-only pools)"), MONITOR],
  [ref("Performance standby nodes", f"{D}/docs/enterprise/performance-standby")], ["Code: 500. Errors:\n\n* please forward to the active node"],
  probe="please forward to the active node")
add("ha-leadership-lost", "Leadership lost / stepping down", "ha", "both",
  [r"leadership lost, stopping active operation", r"shutdown while waiting for leadership", r"leader advertisement setup failed", r"clearing leader advertisement failed", r"audit device configuration failed, skipping HA lock acquisition"],
  "The active node lost leadership and stepped down, or a node cannot become active.",
  ["Post-unseal setup failed (for example an audit device could not start), so Vault will not take the lock.", "Manual step-down."],
  ["Storage/HA backend lost the lock or quorum.", "Audit sink (file/socket/syslog) not available."],
  [STATUS, PEERS, s("Check the log lines right before the step-down for the real error"), s("If an audit device failed, check its file path/socket", "vault audit list -detailed")],
  [R_HA], ["[WARN]  core: leadership lost, stopping active operation"],
  probe="leadership lost, stopping active operation")
add("ha-cluster-listener", "Cluster listener / cluster TLS error", "ha", "internal",
  [r"clustering not disabled but no addresses to listen on", r"no cluster listener configured", r"failed to get tls configuration when starting cluster listener", r"cluster addresses not found", r"no local cluster cert found", r"(got )?forwarding connection (client )?but no local cert", r"error parsing local cluster certificate"],
  "Vault could not start the cluster (8201) listener or load its internal cluster certificate.",
  ["`cluster_addr` missing or not matching a listener address.", "Node not unsealed yet, so cluster certificates are not loaded."], [],
  [CONFIGCHK, STATUS, s("Confirm something listens on the cluster port", "ss -ltnp | grep 8201")],
  [R_HA, ref("cluster_addr parameter", f"{D}/docs/configuration#cluster_addr")], ["[ERROR] core: clustering not disabled but no addresses to listen on"],
  probe="clustering not disabled but no addresses to listen on")
add("ha-x-forwarded-for", "X-Forwarded-For rejected", "ha", "both",
  [r"client address not authorized for x-forwarded-for", r"missing x-forwarded-for header and configured to reject", r"malformed x-forwarded-for"],
  "The listener's X-Forwarded-For settings rejected the request from the load balancer.",
  ["`x_forwarded_for_authorized_addrs` missing the LB's subnet.", "`x_forwarded_for_reject_not_present` set while some paths bypass the LB."],
  ["Load balancer not adding the header, or adding multiple hops."],
  [s("Review x_forwarded_for_* settings on the listener", "grep -E 'x_forwarded_for' /etc/vault.d/vault.hcl"), s("Confirm LB source IPs and header behaviour")],
  [R_TCP], ["Code: 403. Errors:\n\n* client address not authorized for x-forwarded-for and configured to reject connection"],
  probe="client address not authorized for x-forwarded-for")

# ---------------- NETWORK ----------------
add("network-connection-refused", "Connection refused / timeout reaching Vault", "network", "external",
  [r"dial tcp .*: connect: connection refused", r"dial tcp .*: i/o timeout", r"dial tcp: lookup .*: no such host", r"connect: no route to host", r"connection reset by peer"],
  "The client could not open a TCP connection. Vault is down, listening elsewhere, or the network path is blocked.",
  ["VAULT_ADDR points at the wrong host/port.", "Listener bound to 127.0.0.1 only."],
  ["Vault process not running or crash-looping.", "Firewall, security group or Kubernetes Service/NetworkPolicy blocking the port.", "DNS failure."],
  [s("Check VAULT_ADDR", "echo $VAULT_ADDR"), s("Check the process and listening sockets on the server", "systemctl status vault; ss -ltnp | grep 820"), s("Test the path from the client", "nc -zv <host> 8200"), JOURNAL],
  [R_TCP], ["Error checking seal status: Get \"https://vault:8200/v1/sys/seal-status\": dial tcp 10.0.0.11:8200: connect: connection refused"],
  probe="", origin="Go net (client side)")
add("network-too-many-open-files", "Too many open files", "network", "external",
  [r"too many open files", r"accept4: too many open files"],
  "Vault hit the file descriptor limit, so it cannot accept connections or open storage files.",
  ["Client connection leak (no keep-alive reuse) or very many leases/plugins."],
  ["LimitNOFILE too low in the systemd unit / container."],
  [s("Check limits and current usage", "cat /proc/$(pidof vault)/limits | grep 'open files'; ls /proc/$(pidof vault)/fd | wc -l"), s("Raise LimitNOFILE (e.g. 65536) in the unit and restart", "systemctl edit vault")],
  [R_CONFIG], ["[ERROR] http: Accept error: accept tcp [::]:8200: accept4: too many open files; retrying in 1s"],
  probe="", origin="Linux / Go net")
add("network-plugin-exited", "Plugin process failed to start", "network", "both",
  [r"plugin exited before we could connect", r"Unrecognized remote plugin message", r"Incompatible API version with plugin", r"plugin.*(checksum|sha256) (mismatch|does not match)"],
  "An external plugin binary failed to start or speak the plugin protocol.",
  ["Plugin registered with the wrong SHA256 or not registered after upgrade.", "`plugin_directory` wrong."],
  ["Binary built for another OS/arch, missing libraries (e.g. Oracle Instant Client), or noexec mount.", "mlock or memory limits killing the plugin."],
  [s("Check the registration", "vault plugin info <type> <name>"), s("Recompute the checksum and compare", "sha256sum <plugin_directory>/<binary>"), s("Run the binary by hand as the vault user to see linker errors", "sudo -u vault <plugin_directory>/<binary> --help")],
  [R_PLUGIN], ["[ERROR] secrets.database.database_1234: error creating database object: error=\"Unrecognized remote plugin message: \n\nThis usually means that the plugin is either invalid or simply\nneeds to be recompiled to support the latest protocol.\""],
  probe="Unrecognized remote plugin message")

# ---------------- TOKEN / LEASE ----------------
add("network-listener-bind", "Listener cannot bind its address", "network", "external",
  [r"listen tcp .*: bind: (permission denied|address already in use|cannot assign requested address)", r"bind: address already in use", r"Error initializing listener of type tcp: listen tcp"],
  "Vault could not open its API or cluster listener socket. This is an OS-level problem with the address or port, not a Vault token or policy problem.",
  ["Two listener stanzas (or api/cluster addresses) use the same port.", "Listener address is an IP that does not exist on this host."],
  ["Another process (or an old Vault) already holds the port.", "Port below 1024 without CAP_NET_BIND_SERVICE for the vault user.", "SELinux/AppArmor denies the bind."],
  [s("Find what already holds the port", "sudo ss -ltnp | grep -E ':8200|:8201'"), s("Check the listener address and cluster_address in the config", "grep -nE 'address|cluster_address' /etc/vault.d/vault.hcl"), s("For ports below 1024, add the bind capability while keeping cap_ipc_lock (setcap replaces the whole set; check getcap first)", "getcap $(readlink -f $(which vault)); sudo setcap cap_ipc_lock,cap_net_bind_service=+ep $(readlink -f $(which vault))"), s("Check SELinux denials", "sudo ausearch -m avc -ts recent | grep vault")],
  [R_TCP], ["Error initializing listener of type tcp: listen tcp 0.0.0.0:443: bind: permission denied", "Error initializing listener of type tcp: listen tcp 0.0.0.0:8200: bind: address already in use"],
  probe="", origin="Go net listener bind error surfaced by Vault at startup")
add("token-permission-denied", "Permission denied", "token", "internal",
  [r"^(?!.*(?:bind|open [^:]+|mkdir [^:]+|stat [^:]+|lstat [^:]+|chmod [^:]+|chown [^:]+): permission denied).*\bpermission denied\b", r"Code: 403\. Errors:\s*\*\s*(1 error occurred:\s*\*\s*)?permission denied"],
  "The token's ACL policies do not allow the operation on that path, or the token is invalid/expired (Vault returns 403 in both cases).",
  ["Policy lacks the capability (read/create/update/list/sudo) on the exact path (KV v2 needs data/ and metadata/).", "Token expired, revoked, or used in the wrong namespace.", "Sentinel/EGP or control group denial (Enterprise)."],
  ["Client sends the wrong token (stale VAULT_TOKEN, agent cache).", "Auth method backend changed group/role mapping."],
  [TOKLOOK, CAPS, s("Read the attached policies", "vault policy read <policy>"), AUDITQ, s("Confirm namespace", "echo $VAULT_NAMESPACE")],
  [R_POLICY, R_TOKENS], ["Error reading secret/data/app: Error making API request.\n\nURL: GET https://vault:8200/v1/secret/data/app\nCode: 403. Errors:\n\n* permission denied"],
  probe="permission denied")
add("token-bad-token", "Invalid / malformed token", "token", "internal",
  [r"\bbad token\b", r"can'?t decode token", r"cannot decode token", r"invalid token", r"cannot lookup blank token"],
  "The client sent a token that is malformed or unknown.",
  ["Token truncated, wrong prefix (hvs./hvb./s.), or from another cluster.", "Batch token used on a cluster other than where it was created (without replication)."],
  ["Proxy or app config mangling the X-Vault-Token header."],
  [TOKLOOK, s("Log in again to get a fresh token", "vault login -method=<method>"), AUDITQ],
  [R_TOKENS], ["Code: 403. Errors:\n\n* bad token"],
  probe="bad token")
add("token-lease-not-found", "Lease not found / expired", "token", "internal",
  [r"lease not found", r"invalid lease ID", r"lease expired", r"cannot renew lease, no valid associated token", r"invalid lease"],
  "The lease ID is unknown or already expired/revoked, so it cannot be renewed or revoked.",
  ["App renewing after max_ttl.", "Parent token revoked, which revoked child leases.", "Lease from another cluster/namespace."], [],
  [s("Look up the lease", "vault lease lookup <lease_id>"), s("Check the mount's default/max TTL", "vault read sys/mounts/<mount>/tune"), TOKLOOK],
  [R_LEASE], ["Error renewing lease: Code: 400. Errors:\n\n* lease not found"],
  probe="lease not found")
add("token-batch-limits", "Batch token limitations", "token", "internal",
  [r"batch tokens cannot (be renewed|be revoked|create more tokens|be root tokens)", r"cannot register a lease for a batch token", r"'token_type' cannot be 'batch' when role is set to generate"],
  "Batch tokens are lightweight and cannot be renewed, revoked, create children or be root.",
  ["Role or auth method uses token_type=batch for a workload that needs renewal or child tokens."], [],
  [TOKLOOK, s("Check the role's token_type", "vault read auth/<mount>/role/<role>"), s("Switch to service tokens or adjust the client")],
  [ref("Batch tokens", f"{D}/docs/concepts/tokens#batch-tokens")], ["Code: 400. Errors:\n\n* batch tokens cannot be renewed"],
  probe="batch tokens cannot be renewed")
add("token-revocation-failed", "Lease revocation failing / irrevocable", "token", "both",
  [r"failed to revoke lease", r"failed to revoke entry", r"hit max irrevocable leases", r"lease is expired and has failed previous revocation attempts", r"failed to revoke an invalid lease", r"failed to mark lease as irrevocable"],
  "Vault keeps failing to revoke leases. The secrets engine cannot delete the credential at the target system.",
  ["Secrets engine config broken (root credential rotated outside Vault)."],
  ["Target DB/cloud unreachable or root credentials lack DROP/delete permission.", "Target user already deleted manually."],
  [s("List irrevocable leases", "vault list -format=json sys/leases/lookup/<mount>/creds/<role> | head"), s("Check the error on irrevocable leases", "vault read sys/leases/count; vault read -format=json sys/leases?type=irrevocable"), s("Test the secrets engine connection", "vault read <mount>/config/<name>"), s("After fixing the target, retry revoking the single failed lease", "vault lease revoke <lease_id>"), s("Only if that credential is confirmed gone from the target system, force-revoke that one lease (removes it from Vault without contacting the target)", "vault lease revoke -force <lease_id>")],
  [R_LEASE], ["[ERROR] expiration: failed to revoke lease: lease_id=database/creds/app/abc123 error=\"failed to revoke entry: resp: (*logical.Response)(nil) err: dial tcp 10.0.2.5:5432: i/o timeout\""],
  probe="failed to revoke lease")
add("token-restoring-leases", "Error restoring leases on unseal", "token", "both",
  [r"error restoring leases", r"barrier sealed while restoring leases", r"context canceled while restoring leases"],
  "Loading leases into the expiration manager after unseal/leadership failed or was interrupted.",
  ["Very large number of leases (often millions from short-lived tokens) makes leadership changes slow."],
  ["Storage latency during lease restore."],
  [s("Check lease counts", "vault read sys/leases/count -format=json 2>/dev/null || vault read sys/internal/counters/tokens"), s("Check vault.expire.num_leases metric", "curl -s -H \"X-Vault-Token: $VAULT_TOKEN\" $VAULT_ADDR/v1/sys/metrics | jq '.Gauges[] | select(.Name==\"vault.expire.num_leases\")'"), s("Reduce lease TTLs / use batch tokens for high-volume logins")],
  [R_LEASE, R_QUOTA], ["[ERROR] expiration: error restoring leases: error=\"context deadline exceeded\""],
  probe="error restoring leases")
add("token-quota-exceeded", "Rate limit / lease count quota exceeded", "token", "internal",
  [r"rate limit quota exceeded", r"lease count quota exceeded", r"Code: 429.*quota"],
  "A resource quota rejected the request (HTTP 429 for rate limits).",
  ["Quota too low for the workload.", "Retry storm or runaway client creating tokens/leases."], [],
  [s("List quotas", "vault list sys/quotas/rate-limit; vault list sys/quotas/lease-count"), s("Read the quota that matched", "vault read sys/quotas/rate-limit/<name>"), AUDITQ],
  [R_QUOTA], ["Error making API request.\n\nCode: 429. Errors:\n\n* rate limit quota exceeded"],
  probe="rate limit quota exceeded")
add("token-ttl-limits", "Token TTL exceeds allowed maximum", "token", "internal",
  [r"explicit max TTL of .* is greater than system/mount allowed value", r"explicit_max_ttl must be positive", r"TTL .* is longer than permitted maxTTL", r"token ttl should not be greater than token max ttl"],
  "Requested or configured TTL is above the mount/system max TTL, so Vault caps it.",
  ["Role max TTL higher than mount `max_lease_ttl` or system default (32 days)."], [],
  [s("Check mount tuning", "vault read sys/auth/<mount>/tune"), s("Check the role TTLs", "vault read auth/<mount>/role/<role>"), s("Tune the mount if a longer TTL is intended", "vault auth tune -max-lease-ttl=<dur> <mount>")],
  [R_TOKENS, R_LEASE], ["[WARN]  Given explicit max TTL of 8760h is greater than system/mount allowed value of 768h seconds"],
  probe="is greater than system/mount allowed value")
add("token-namespace-mismatch", "Token or lease used across namespaces", "token", "internal",
  [r"cannot renew a (token|lease) across namespaces", r"error looking up namespace from the (token|lease)'s namespace ID", r"failed to fetch token'?s? namespace"],
  "A token or lease is used from a namespace different from where it was created.",
  ["Client sets VAULT_NAMESPACE (or X-Vault-Namespace) differently for login and renew."], [],
  [TOKLOOK, s("Check the namespace the client sends", "echo $VAULT_NAMESPACE"), s("Renew/revoke from the namespace that issued the token")],
  [ref("Namespaces", f"{D}/docs/enterprise/namespaces")], ["Code: 403. Errors:\n\n* cannot renew a token across namespaces"],
  probe="cannot renew a token across namespaces")

# ---------------- AUTH ----------------
add("auth-aws-binding", "AWS auth role binding mismatch", "auth", "both",
  [r"IAM Principal .* does not belong to the role", r"IAM role ARN does not satisfy the constraint on role", r"account ID does not belong to role", r"AMI ID does not belong to role", r"VPC ID does not satisfy the constraint", r"IAM instance profile ARN does not satisfy the constraint"],
  "The AWS identity that logged in does not match the bound_* constraints on the Vault role.",
  ["Role bound_iam_principal_arn / bound_account_id / bound_vpc_id wrong.", "Principal ARN changed (role recreated) and Vault cached the old unique ID."],
  ["Workload uses another role (assumed role, IRSA, cross-account) than expected."],
  [AWSID, s("Read the Vault role bindings", "vault read auth/aws/role/<role>"), s("Re-save the role to refresh resolved principal IDs", "vault write auth/aws/role/<role> bound_iam_principal_arn=<arn>")],
  [RAUTH("aws", "AWS")], ["Error authenticating: Code: 400. Errors:\n\n* IAM Principal \"arn:aws:sts::123456789012:assumed-role/app/i-0abc\" does not belong to the role \"app\""],
  probe="does not belong to the role")
add("auth-aws-sts", "AWS auth STS call failed", "auth", "external",
  [r"error making upstream request", r"body of GetCallerIdentity is invalid", r"SignatureDoesNotMatch", r"InvalidClientTokenId", r"iam_server_id_header_value", r"X-Vault-AWS-IAM-Server-ID"],
  "Vault could not verify the signed sts:GetCallerIdentity request from the client.",
  ["iam_server_id_header_value set in Vault but not sent by the client (or the reverse).", "STS endpoint/region config mismatch (sts_endpoint, sts_region)."],
  ["Client clock skew breaks the signature.", "Vault cannot reach STS (proxy, VPC endpoint).", "Expired client credentials."],
  [s("Check Vault's AWS client config", "vault read auth/aws/config/client"), s("Check client clock", "timedatectl status"), s("From the Vault host, confirm STS is reachable", "curl -sv https://sts.amazonaws.com 2>&1 | head")],
  [RAUTH("aws", "AWS")], ["Error authenticating: Code: 400. Errors:\n\n* error making upstream request: received error code 403 from STS: <ErrorResponse><Error><Code>SignatureDoesNotMatch</Code>"],
  probe="error making upstream request")
add("auth-kubernetes", "Kubernetes auth login failed", "auth", "both",
  [r"service account name not authorized", r"namespace not authorized", r"lookup failed: service account (unauthorized|jwt not valid)", r"lookup failed: service account jwt valid for audience", r"could not load backend configuration", r"tokenreviews.* is forbidden", r"invalid expiration time \(exp\) claim: token is expired"],
  "Vault could not validate the pod's service account JWT, or the SA/namespace is not bound to the role.",
  ["Role bound_service_account_names / namespaces do not include the pod's SA.", "`audience` on the role does not match the projected token audience.", "kubernetes_host / CA config wrong."],
  ["Vault's reviewer token lacks system:auth-delegator (TokenReview forbidden).", "SA deleted/recreated, or short-lived token expired.", "Vault cannot reach the Kubernetes API."],
  [s("Read the role bindings", "vault read auth/kubernetes/role/<role>"), s("Read the auth config", "vault read auth/kubernetes/config"), s("Check auth-delegator binding for the reviewer SA", "kubectl get clusterrolebinding -o wide | grep auth-delegator"), s("Decode the pod JWT to see sa, namespace, aud", "kubectl exec <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d 2>/dev/null | jq")],
  [RAUTH("kubernetes", "Kubernetes")], ["Error authenticating: Code: 403. Errors:\n\n* service account name not authorized"],
  probe="service account name not authorized")
add("auth-ldap", "LDAP auth bind/search failure", "auth", "external",
  [r"LDAP Result Code \d+", r"bind \(service\) failed", r"LDAP search (for binddn )?failed", r"discovery of user bind DN failed", r"ldap: (failed to connect|error connecting to host)", r"ldap backend not configured", r"cannot derive UserBindDN"],
  "Vault could not connect, bind, or find the user/groups in the LDAP directory.",
  ["Wrong url, userdn, userattr, groupdn, groupfilter or upndomain.", "binddn/bindpass wrong or rotated."],
  ["Directory unreachable (port 389/636), or TLS CA not trusted.", "User locked/disabled (Result Code 49 Invalid Credentials)."],
  [s("Read the auth config", "vault read auth/ldap/config"), s("Reproduce the bind from the Vault host", "ldapsearch -H <url> -D '<binddn>' -W -b '<userdn>' '(<userattr>=<user>)'"), s("Check TLS to the directory", "openssl s_client -connect <ldap-host>:636 </dev/null")],
  [RAUTH("ldap", "LDAP")], ["Error authenticating: Code: 400. Errors:\n\n* ldap operation failed: failed to bind as user: LDAP Result Code 49 \"Invalid Credentials\""],
  probe="discovery of user bind DN failed")
add("auth-cert", "TLS certificate auth failed", "auth", "both",
  [r"client certificate must be supplied", r"failed to verify client'?s certificate", r"no client certificate found", r"certificate mismatch of a trusted leaf certificate", r"invalid certificate or no client certificate supplied"],
  "Cert auth did not receive a client certificate, or the cert does not chain to a trusted cert on any role.",
  ["CA not registered in auth/cert/certs/<role>, or allowed_* constraints too strict."],
  ["Load balancer terminates TLS so the client cert never reaches Vault.", "Listener tls_disable_client_certs = true."],
  [s("List trusted cert roles", "vault list auth/cert/certs"), s("Test with the client cert directly against a node", "vault login -method=cert -client-cert=client.pem -client-key=client.key"), s("Use TCP passthrough on the LB for cert auth")],
  [RAUTH("cert", "TLS certificates")], ["Error authenticating: Code: 400. Errors:\n\n* client certificate must be supplied"],
  probe="client certificate must be supplied")
add("auth-approle", "AppRole login failed", "auth", "internal",
  [r"invalid role or secret ID", r"invalid secret id", r"source address .* unauthorized", r"bind_secret_id is not set on the role", r"SecretID is already registered"],
  "AppRole rejected the role_id/secret_id pair or the source IP.",
  ["secret_id expired, used up (secret_id_num_uses) or from another role.", "secret_id_bound_cidrs / token_bound_cidrs exclude the client."],
  ["Client IP changed (NAT, LB) compared to bound CIDRs."],
  [s("Look up the secret ID accessor", "vault write auth/approle/role/<role>/secret-id-accessor/lookup secret_id_accessor=<accessor>"), s("Read role constraints", "vault read auth/approle/role/<role>"), AUDITQ],
  [RAUTH("approle", "AppRole")], ["Error writing data to auth/approle/login: Code: 400. Errors:\n\n* invalid role or secret ID"],
  probe="invalid role or secret ID")
add("auth-userpass", "Invalid username or password", "auth", "internal",
  [r"invalid username or password", r"invalid credentials"],
  "Userpass (or similar) login rejected the credentials.",
  ["Wrong password, wrong mount path, or user missing.", "User lockout after repeated failures."], [],
  [s("Check the user exists on the mount", "vault list auth/userpass/users"), s("Check user lockout", "vault read sys/locked-users"), AUDITQ],
  [RAUTH("userpass", "Userpass"), ref("User lockout", f"{D}/docs/concepts/user-lockout")], ["Error authenticating: Code: 400. Errors:\n\n* invalid username or password"],
  probe="invalid username or password")

# ---------------- PKI ----------------
add("pki-role-not-allowed", "PKI role does not allow the requested name", "pki", "internal",
  [r"(common name|subject alternate name|email address|other SAN OID|serial_number) .* not allowed by this role", r"IP Subject Alternative Names are not allowed in this role", r"role \(.*\) will not issue certificate for name"],
  "The PKI role's allowed_domains / allow_* flags do not permit the requested CN or SANs.",
  ["allowed_domains missing the domain, or allow_subdomains / allow_glob_domains / allow_bare_domains not set.", "allow_ip_sans false."], [],
  [s("Read the role", "vault read <pki_mount>/roles/<role>"), s("Update only the role constraints you need (patch keeps the other role settings; `vault write` would reset them)", "vault patch <pki_mount>/roles/<role> allowed_domains=example.com allow_subdomains=true")],
  [R_PKI], ["Error writing data to pki/issue/web: Code: 400. Errors:\n\n* common name app.internal.example.org not allowed by this role"],
  probe="not allowed by this role")
add("pki-issuer-missing", "PKI issuer missing or unusable", "pki", "internal",
  [r"no default issuer currently configured", r"issuer does not exist", r"issuer missing proper issuance usage or key", r"unable to fetch corresponding key for issuer", r"could not fetch the CA certificate \(was one set\?\)"],
  "The PKI mount has no usable issuer (none generated/imported, default not set, or key missing).",
  ["Mount never got a root/intermediate.", "Default issuer deleted, or issuer has leaf_not_after_behavior/usage limits."],
  ["Managed key (HSM/KMS) for the issuer unavailable (Enterprise)."],
  [s("List issuers", "vault list <pki_mount>/issuers"), s("Check the default issuer", "vault read <pki_mount>/config/issuers"), s("Set the default", "vault write <pki_mount>/config/issuers default=<issuer_ref>")],
  [R_PKI], ["Code: 500. Errors:\n\n* no default issuer currently configured"],
  probe="no default issuer currently configured")
add("pki-ttl-beyond-ca", "Certificate TTL beyond CA expiration", "pki", "internal",
  [r"beyond the expiration of the CA certificate", r"not_after .* longer than permitted maxTTL"],
  "The requested cert would outlive the issuing CA, and leaf_not_after_behavior is `err`.",
  ["Intermediate CA near expiry.", "Requested TTL too long."], [],
  [s("Check CA expiry", "vault read -field=certificate <pki_mount>/issuer/default | openssl x509 -noout -enddate"), s("Rotate the intermediate, lower the TTL, or set leaf_not_after_behavior=truncate", "vault write <pki_mount>/issuer/default leaf_not_after_behavior=truncate")],
  [R_PKI, ref("PKI rotation primitives", f"{D}/docs/secrets/pki/rotation-primitives")], ["Code: 400. Errors:\n\n* cannot satisfy request, as TTL would result in notAfter of 2026-01-01T00:00:00Z that is beyond the expiration of the CA certificate at 2025-06-01T00:00:00Z"],
  probe="beyond the expiration of the CA certificate")
add("pki-crl-build", "PKI CRL build failure", "pki", "both",
  [r"Error building CRLs", r"CRL was not updated, as it exceeds the configured max size", r"Rebuilding the CRL failed"],
  "Vault could not build or update the CRL for one or more issuers.",
  ["Very many revoked, unexpired certificates (no tidy).", "Imported issuer needs revocation_signature_algorithm (PSS-only managed keys)."],
  ["Managed key/HSM unavailable for signing."],
  [s("Run tidy to drop expired revoked certs", "vault write <pki_mount>/tidy tidy_cert_store=true tidy_revoked_certs=true safety_buffer=72h"), s("Check CRL config", "vault read <pki_mount>/config/crl"), s("Force a rebuild", "vault read <pki_mount>/crl/rotate")],
  [R_PKI, ref("PKI considerations", f"{D}/docs/secrets/pki/considerations")], ["[ERROR] secrets.pki: CRL was not updated, as it exceeds the configured max size.  The CRL now does not contain all revoked certificates!"],
  probe="CRL was not updated, as it exceeds the configured max size")
add("pki-migration-pending", "PKI issuer migration not complete", "pki", "internal",
  [r"Can not .* until migration has completed"],
  "After an upgrade the PKI mount is still migrating legacy CA storage to the multi-issuer layout.",
  ["Upgrade in progress; on replicated clusters the primary must finish first."], [],
  [s("Wait and retry; check the server log for PKI migration messages", "vault monitor -log-level=debug | grep -i pki"), STATUS],
  [R_PKI], ["Code: 500. Errors:\n\n* Can not get issuer until migration has completed"],
  probe="until migration has completed")

# ---------------- TRANSIT ----------------
add("transit-key-not-found", "Transit key not found", "transit", "internal",
  [r"encryption key not found", r"key .* not found", r"error retrieving wrapping key"],
  "The named transit key does not exist on this mount/namespace.",
  ["Wrong key name, mount path or namespace.", "Key deleted (deletion_allowed)."], [],
  [s("List keys", "vault list <transit_mount>/keys"), s("Read the key", "vault read <transit_mount>/keys/<name>")],
  [R_TRANSIT], ["Code: 400. Errors:\n\n* encryption key not found"],
  probe="encryption key not found")
add("transit-version-too-old", "Transit key version too old", "transit", "internal",
  [r"version is too old \(disallowed by policy\)", r"cannot use key version", r"invalid ciphertext: version is too new"],
  "The ciphertext uses a key version below min_decryption_version (or above the latest).",
  ["min_decryption_version raised after rotation without rewrapping data.", "Ciphertext from another cluster/key."], [],
  [s("Check key versions", "vault read <transit_mount>/keys/<name>"), s("Rewrap data to the latest version", "vault write <transit_mount>/rewrap/<name> ciphertext=<ct>"), s("Lower min_decryption_version if needed", "vault write <transit_mount>/keys/<name>/config min_decryption_version=<n>")],
  [R_TRANSIT], ["Code: 400. Errors:\n\n* cannot use key version 1: version is too old (disallowed by policy) for key app"],
  probe="version is too old (disallowed by policy)")
add("transit-invalid-ciphertext", "Invalid transit ciphertext", "transit", "internal",
  [r"invalid ciphertext: (no prefix|wrong number of fields|could not decode base64|version number could not be decoded)", r"cipher: message authentication failed", r"invalid ciphertext length"],
  "The ciphertext is malformed, truncated, or was encrypted with another key/context.",
  ["App stores only part of the vault:vN:... string.", "Derived key decrypted without the same context.", "Wrong key name."], [],
  [s("Check the ciphertext starts with vault:v<N>:"), s("Make sure context/nonce match the encrypt call"), s("Confirm the key name used for encrypt", "vault read <transit_mount>/keys/<name>")],
  [R_TRANSIT], ["Code: 400. Errors:\n\n* invalid ciphertext: no prefix"],
  probe="invalid ciphertext: no prefix")

# ---------------- AUDIT ----------------
add("audit-device-failed", "Audit device failed / not accessible", "audit", "external",
  [r"audit backend failed test message", r"audit device not accessible at startup", r"file sink creation failed for path", r"error creating syslog sink", r"audit system internal error", r"failed to close file audit backend"],
  "An audit device could not write. If every enabled device fails, Vault blocks requests so it never serves an unaudited request.",
  ["Audit path changed in config/API without creating the directory."],
  ["Disk full or volume read-only.", "File owned by another user (logrotate created it as root).", "Socket target down / syslog daemon not running."],
  [s("List devices and options", "vault audit list -detailed"), s("Check disk and permissions", "df -h /var/log/vault && ls -la /var/log/vault"), s("Check logrotate uses copytruncate or sends SIGHUP to Vault", "cat /etc/logrotate.d/vault"), s("Enable a second device so one failure does not block Vault", "vault audit enable -path=file2 file file_path=/var/log/vault/audit2.log")],
  [R_AUDIT, ref("File audit device", f"{D}/docs/audit/file")], ["[ERROR] audit: backend failed to log request: backend=file/ error=\"file sink creation failed for path \\\"/var/log/vault/audit.log\\\": open /var/log/vault/audit.log: permission denied\"", "Code: 500. Errors:\n\n* audit system internal error"],
  probe="audit system internal error")
add("audit-path-invalid", "Audit file path not allowed", "audit", "internal",
  [r"audit file target may not be in the plugin directory", r"error resolving audit file path for audit validation", r"audit prefix may not contain control characters"],
  "Vault rejected the audit device options during enable.",
  ["file_path inside plugin_directory, or invalid prefix."], [],
  [s("Choose a dedicated audit directory outside plugin_directory", "vault audit enable file file_path=/var/log/vault/audit.log")],
  [R_AUDIT], ["Code: 400. Errors:\n\n* audit file target may not be in the plugin directory"],
  probe="audit file target may not be in the plugin directory")

# ---------------- IDENTITY ----------------
add("identity-entity-invalid", "Entity on token disabled or invalid", "identity", "internal",
  [r"permission denied as the entity on the token is (invalid|disabled)"],
  "The token is tied to an identity entity that is disabled or no longer exists.",
  ["Operator set disabled=true on the entity.", "Entity deleted/merged while tokens were still valid."], [],
  [TOKLOOK, s("Read the entity", "vault read identity/entity/id/<entity_id>"), s("Re-enable it, or log in again to get a token for the current entity", "vault write identity/entity/id/<entity_id> disabled=false")],
  [R_IDENT], ["Code: 403. Errors:\n\n* permission denied as the entity on the token is disabled"],
  probe="permission denied as the entity on the token is disabled")
add("identity-alias-conflict", "Identity alias conflict", "identity", "internal",
  [r"alias with combination of mount accessor and name already exists", r"alias already exists for requested entity and mount accessor", r"alias cannot be updated as the (given )?entity already has an alias", r"Entity has multiple aliases on the same mount"],
  "An entity alias for this mount accessor and name already exists, or an entity would get two aliases on one mount.",
  ["Automation creating aliases twice.", "Merging entities that both have aliases on the same mount."], [],
  [s("Look up the alias by name and mount accessor", "vault write identity/lookup/entity alias_name=<name> alias_mount_accessor=<accessor>"), s("Merge entities and pick the alias to keep", "vault write identity/entity/merge from_entity_ids=<id> to_entity_id=<id> conflicting_alias_ids_to_keep=<alias_id>")],
  [R_IDENT], ["Code: 400. Errors:\n\n* alias with combination of mount accessor and name already exists"],
  probe="alias with combination of mount accessor and name already exists")
add("identity-duplicates", "Identity duplicates detected", "identity", "internal",
  [r"DUPLICATES DETECTED", r"\d+ (different-case )?(local )?entity (alias )?duplicates found", r"\d+ group duplicates found"],
  "On unseal Vault found duplicate entities, aliases or groups (often only case differences) from older versions.",
  ["Historical bugs or case-insensitive identity created duplicates."], [],
  [s("Collect the following log lines that list duplicates"), s("Follow the deduplication guide before upgrading or enabling strict mode")],
  [ref("Identity deduplication", f"{D}/docs/secrets/identity/deduplication")], ["[WARN]  identity: DUPLICATES DETECTED, see following logs for details and refer to https://developer.hashicorp.com/vault/docs/upgrading/identity-deduplication for resolution."],
  probe="DUPLICATES DETECTED")

# ---------------- REPLICATION ----------------
add("replication-keys-changed", "Encryption keys changed (replication enabled)", "replication", "internal",
  [r"encryption keys have changed out from underneath us"],
  "Enabling replication as a secondary replaced this cluster's keyring with the primary's, so the node must be unsealed again.",
  ["Secondary activation, or a node lagging after activation."], [],
  [STATUS, s("Unseal with the primary's unseal/recovery keys (auto-unseal will retry)", "vault operator unseal"), s("Check replication status", "vault read sys/replication/status")],
  [R_REPL], ["[ERROR] core: encryption keys have changed out from underneath us (possibly due to replication enabling), must be unsealed again"],
  probe="encryption keys have changed out from underneath us")
add("replication-primary-only", "Operation only allowed on primary", "replication", "internal",
  [r"rekeying can only be performed on the primary cluster", r"cannot rotate on a replication secondary", r"token hmac key has not been initialized or has not been replicated yet"],
  "The operation must run on the primary, or replicated state has not arrived yet.",
  ["Running rekey/rotate on a secondary.", "Secondary still bootstrapping after activation."], [],
  [s("Check replication mode", "vault read sys/replication/status"), s("Run the operation on the primary cluster"), MONITOR],
  [R_REPL], ["Code: 400. Errors:\n\n* rekeying can only be performed on the primary cluster when replication is activated"],
  probe="rekeying can only be performed on the primary cluster")
add("replication-connection", "Replication connectivity / state errors", "replication", "external",
  [r"replication.*(connection refused|i/o timeout|context deadline exceeded|transport: Error while dialing|connection error)"],
  "Replication traffic between clusters (cluster port 8201, gRPC) fails, or replication state is not yet known.",
  ["primary_cluster_addr wrong or points at a load balancer that is not TCP passthrough.", "Secondary activation token expired."],
  ["Firewall between data centers blocks 8201.", "TLS-inspecting middlebox on 8201."],
  [s("Check status on both clusters", "vault read -format=json sys/replication/status | jq .data"), s("Check the primary cluster address the secondary uses", "vault read sys/replication/performance/status"), s("Test the cluster port from the secondary", "nc -zv <primary-cluster-addr> 8201"), MONITOR],
  [R_REPL, ref("Replication monitoring", f"{D}/tutorials/monitoring/monitor-replication")], ["[ERROR] replication: error=\"rpc error: code = Unavailable desc = connection error: desc = \\\"transport: Error while dialing dial tcp 10.1.0.11:8201: i/o timeout\\\"\""],
  probe="", origin="Vault Enterprise replication (gRPC over the cluster port)")

# ------------- resolve sources -------------
def find(lit):
  for repo, (slug, br) in REPOS.items():
    r = subprocess.run(["grep", "-rlF", "--include=*.go", "--exclude=*_test.go", lit, repo], capture_output=True, text=True).stdout.split()
    r = [p for p in r if "/testhelpers/" not in p and "external_tests" not in p and "/vendor/" not in p]
    if r:
      r.sort(key=lambda p: (p.count("/"), p))
      rel = os.path.relpath(r[0], repo)
      return {"repo": slug, "path": rel, "url": f"https://github.com/{slug}/blob/{br}/{rel}"}
  return None
out = []
for e in E:
  for p in e["patterns"]: re.compile(p, re.I)
  probe, origin = e.pop("_probe"), e.pop("_origin")
  src = find(probe) if probe else None
  if probe and not src: raise SystemExit(f"probe not found: {e['id']}: {probe}")
  e["source"] = src or {"repo": None, "note": origin}
  if src: e["references"] = e["references"] + [ref(f"Source: {src['repo']}/{src['path']}", src["url"])]
  out.append(e)
ids = [e["id"] for e in out]; assert len(ids) == len(set(ids))
json.dump({"version": 1, "generated_from": "hashicorp/vault (main) and related HashiCorp libraries", "entries": out}, open(OUT, "w"), indent=2, ensure_ascii=False)
from collections import Counter
print(len(out), Counter(e["subsystem"] for e in out))
