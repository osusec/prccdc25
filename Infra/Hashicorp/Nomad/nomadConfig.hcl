region = "global"
datacenter = "dc1"
log_level = "INFO"

data_dir = "/opt/nomad"

bind_addr = "0.0.0.0"

server {
  enabled = true
  bootstrap_expect = 3
  server_join {
    retry_join = ["provider=aws tag_key=nomad tag_value=server"]
  }
}

client {
  enabled = true
  servers = ["127.0.0.1"]
}

consul {
  address = "127.0.0.1:8500"
  client_auto_join = true
  server_auto_join = true
}

telemetry {
  prometheus_metrics = true
}