path "database/static-creds/control-db" {
  capabilities = ["read"]
}

path "database/static-roles/demo-db" {
  capabilities = ["read"]
}

path "database/rotate-role/demo-db" {
  capabilities = ["update"]
}
