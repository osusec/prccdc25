api_addr                = "https://127.0.0.1:8200"
cluster_addr            = "https://127.0.0.1:8201"
cluster_name            = "OSUSSEC"
disable_mlock           = true
ui                      = true

listener "tcp" {
address       = "0.0.0.0:8200"
tls_disable = true
}

backend "raft" {
path    = "vault-data/"
node_id = "OSUSSECNODE"
}