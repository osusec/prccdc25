datacenter = "dc1"
data_dir = "/opt/consul"
log_level = "INFO"

bind_addr = "0.0.0.0"
client_addr = "0.0.0.0"

server = true
bootstrap_expect = 3

ui_config {
  enabled = true
}

connect {
  enabled = true
}

retry_join = ["provider=aws tag_key=consul tag_value=server"]

telemetry {
  prometheus_retention_time = "10s"
  disable_hostname = true
}