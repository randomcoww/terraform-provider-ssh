// Copyright (c) HashiCorp, Inc.

// https://github.com/hashicorp/terraform-provider-tls/blob/main/internal/provider/resource_locally_signed_cert_test.go

package provider

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"reflect"
	"testing"
	"time"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceUserCert(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 setTimeForTest("2023-01-01T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: userCertConfig(1, 0),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("ssh_user_cert.test", "ca_key_algorithm", "ECDSA"),
					r.TestCheckResourceAttr("ssh_user_cert.test", "validity_start_time", "2023-01-01T12:00:00Z"),
					r.TestCheckResourceAttr("ssh_user_cert.test", "validity_end_time", "2023-01-01T13:00:00Z"),
					r.TestCheckResourceAttr("ssh_user_cert.test", "ready_for_renewal", "false"),
					r.TestCheckResourceAttrWith("ssh_user_cert.test", "cert_authorized_key", func(value string) error {
						pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(value))
						if err != nil {
							return fmt.Errorf("error parsing cert: %s", err)
						}
						cert, ok := pubKey.(*ssh.Certificate)
						if !ok {
							return fmt.Errorf("got wrong type for public key")
						}

						if expected, got := "testUser", cert.KeyId; got != expected {
							return fmt.Errorf("incorrect KeyId: %v, wanted %v", got, expected)
						}

						if expected, got := uint32(ssh.UserCert), cert.CertType; got != expected {
							return fmt.Errorf("incorrect CertType: %v, wanted %v", got, expected)
						}

						if !time.Unix(int64(cert.ValidAfter), 0).Equal(overridableTimeFunc()) {
							return fmt.Errorf("incorrect ValidAfter: %v", cert.ValidAfter)
						}

						if expected, got := 1*time.Hour, time.Unix(int64(cert.ValidBefore), 0).Sub(overridableTimeFunc()); got != expected {
							return fmt.Errorf("incorrect ValidBefore: %v", cert.ValidBefore)
						}

						principals := []string{
							"test1.local",
							"test2.local",
						}
						if expected, got := principals, cert.ValidPrincipals; !reflect.DeepEqual(got, expected) {
							return fmt.Errorf("incorrect ValidPrincipals: expected: %#v actual: %#v", expected, got)
						}

						permissions := map[string]string{
							"permit-X11-forwarding":   "",
							"permit-agent-forwarding": "",
							"source-address":          "192.168.1.0/24",
						}
						if expected, got := permissions, cert.Extensions; !reflect.DeepEqual(got, expected) {
							return fmt.Errorf("incorrect Permissions.Extensions: expected: %#v actual: %#v", expected, got)
						}

						criticalOptions := map[string]string{
							"permit-port-forwarding": "",
							"permit-pty":             "",
							"force-command":          "/usr/bin/id",
						}
						if expected, got := criticalOptions, cert.CriticalOptions; !reflect.DeepEqual(got, expected) {
							return fmt.Errorf("incorrect Permissions.CriticalOptions: expected: %#v actual: %#v", expected, got)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestResourceUserCertRenewalState(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 setTimeForTest("2023-01-01T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: userCertConfig(10, 2),
				Check:  r.TestCheckResourceAttr("ssh_user_cert.test", "ready_for_renewal", "false"),
			},
			{
				PreConfig:          setTimeForTest("2023-01-01T21:00:00Z"),
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check:              r.TestCheckResourceAttr("ssh_user_cert.test", "ready_for_renewal", "true"),
			},
			{
				PreConfig: setTimeForTest("2023-01-01T21:00:00Z"),
				Config:    userCertConfig(10, 2),
				Check:     r.TestCheckResourceAttr("ssh_user_cert.test", "ready_for_renewal", "false"),
			},
		},
	})
}

func TestResourceUserCertUpdate(t *testing.T) {
	var previousCert string
	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 setTimeForTest("2023-01-01T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: userCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("ssh_user_cert.test", "cert_authorized_key", func(value string) error {
					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2023-01-01T19:00:00Z"),
				Config:    userCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("ssh_user_cert.test", "cert_authorized_key", func(value string) error {
					if value != previousCert {
						return fmt.Errorf("certificate updated even though still time until early renewal")
					}
					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2023-01-01T21:00:00Z"),
				Config:    userCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("ssh_user_cert.test", "cert_authorized_key", func(value string) error {
					if value == previousCert {
						return fmt.Errorf("certificate not updated even though early renewal time has passed")
					}
					previousCert = value
					return nil
				}),
			},
		},
	})
}

func setTimeForTest(timeStr string) func() {
	return func() {
		overridableTimeFunc = func() time.Time {
			t, _ := time.Parse(time.RFC3339, timeStr)
			return t
		}
	}
}

func userCertConfig(validity, earlyRenewal int) string {
	return providerConfig + fmt.Sprintf(`
	resource "ssh_user_cert" "test" {
		ca_private_key_pem = <<EOT
%s
EOT
		public_key_openssh = "%s"
		validity_period_hours = %d
		early_renewal_hours = %d
		key_id = "testUser"
		valid_principals = [
			"test1.local",
			"test2.local",
		]
		extensions = {
			"permit-X11-forwarding"   = ""
			"permit-agent-forwarding" = ""
			"source-address"          = "192.168.1.0/24"
		}
		critical_options = {
			"permit-port-forwarding" = ""
			"permit-pty"             = ""
			"force-command"          = "/usr/bin/id"
		}
	}`, inputPrivateKey, inputPublicKeyOpenSSH, validity, earlyRenewal)
}

const (
	inputPrivateKey = `
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBsATI3ZfiYYuonqeRTZeeSo6nETnuywvDk+gukuKlxL8RSdLzNTsM
YKOUACmd6y7TUMXUbqPp9sHLLyXpI2srQ8+gBwYFK4EEACOhgYkDgYYABADTSGB0
t9y4e4nVpREo+V5jytqMKkOOUJnYTKYbm2XN2HPK01zFOJHHNqmu7uBFKNpOmRIM
gi+o3CilfbQfQZ80swDjZnvsOB3Rmca6dzIJdq0P89B8A7GRGq4zDEITtBVdP7WY
QveKd5z7HM3oQk7wRX0lO8AoWQvNOs+3FtW+g3PG7Q==
-----END EC PRIVATE KEY-----`
	inputPublicKeyOpenSSH = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFM5KbXKVwcM545oB+0XUSI032WtFpk1HS+SW/uy72lS6kWpPItr+nuCHf/m0nSJwXr7s5HhY4ZHEgNtF41cl57IAChc2W/2f2genhG85N49UyRAv+Ex2f5WVMi9E973XqNR5t1xcchAfnVOfbc6Dqpfyh7zkwwr8wNm+CbOoQAcqKjoQ=="
)
