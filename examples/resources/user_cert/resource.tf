# Copyright (c) HashiCorp, Inc.

resource "ssh_user_cert" "test1" {
  ca_private_key_pem    = <<EOT
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBsATI3ZfiYYuonqeRTZeeSo6nETnuywvDk+gukuKlxL8RSdLzNTsM
YKOUACmd6y7TUMXUbqPp9sHLLyXpI2srQ8+gBwYFK4EEACOhgYkDgYYABADTSGB0
t9y4e4nVpREo+V5jytqMKkOOUJnYTKYbm2XN2HPK01zFOJHHNqmu7uBFKNpOmRIM
gi+o3CilfbQfQZ80swDjZnvsOB3Rmca6dzIJdq0P89B8A7GRGq4zDEITtBVdP7WY
QveKd5z7HM3oQk7wRX0lO8AoWQvNOs+3FtW+g3PG7Q==
-----END EC PRIVATE KEY-----
EOT
  public_key_openssh    = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFM5KbXKVwcM545oB+0XUSI032WtFpk1HS+SW/uy72lS6kWpPItr+nuCHf/m0nSJwXr7s5HhY4ZHEgNtF41cl57IAChc2W/2f2genhG85N49UyRAv+Ex2f5WVMi9E973XqNR5t1xcchAfnVOfbc6Dqpfyh7zkwwr8wNm+CbOoQAcqKjoQ=="
  validity_period_hours = 600
  early_renewal_hours   = 300
  key_id                = "testUser"
  valid_principals = [
    "test1.local",
    "test2.local",
  ]
  extensions = [
    "permit-X11-forwarding",
    "permit-agent-forwarding",
  ]
  critical_options = [
    "permit-port-forwarding",
    "permit-pty",
  ]
}