controller {
  name = "boundary-controller"
  description = "Boundary controller configuration"
  database {
    url = "postgres://boundary:password@localhost:5432/boundary?sslmode=disable"
  }
  listener {
    purpose = "api"
    address = "0.0.0.0:9200"
  }
  listener {
    purpose = "cluster"
    address = "0.0.0.0:9201"
  }
}

worker {
  name = "boundary-worker"
  description = "Boundary worker configuration"
  controller_generated_activation_token = "your-activation-token"
  listener {
    purpose = "proxy"
    address = "0.0.0.0:9202"
  }
}

auth_method "password" {
  name = "password-auth"
  description = "Password authentication method"
  primary_auth_method = true
}