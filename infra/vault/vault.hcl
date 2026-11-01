ui = true
disable_mlock = true
# Local maintenance uses the stored Shamir share to authorize a temporary
# provisioning token. The HTTP application never receives this share.
enable_unauthenticated_access = ["generate-root"]
api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"

storage "raft" {
  path = "/vault/data"
  node_id = "coursework-vault"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/server.crt"
  tls_key_file = "/vault/tls/server.key"
  tls_min_version = "tls12"
}
