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
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []r.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
					resource "ssh_user_cert" "test1" {
						ca_private_key_pem = <<EOT
%s
EOT
						public_key_openssh = "%s"
						validity_period_hours = 600
						early_renewal_hours = 300
						key_id = "testUser"
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
					}`, inputPrivateKey, inputPublicKeyOpenSSH),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttrWith("ssh_user_cert.test1", "cert_authorized_key", func(value string) error {
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

						if cert.Signature == nil {
							return fmt.Errorf("incorrect Signature: %v", cert.Signature)
						}

						if time.Unix(int64(cert.ValidAfter), 0).After(time.Now()) {
							return fmt.Errorf("incorrect ValidAfter: %v", cert.ValidAfter)
						}

						if time.Unix(int64(cert.ValidBefore), 0).Before(time.Now()) {
							return fmt.Errorf("incorrect ValidBefore: %v", cert.ValidBefore)
						}

						if expected, got := 600*time.Hour, time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0)); got != expected {
							return fmt.Errorf("incorrect ttl: expected: %v, actual: %v", expected, got)
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
						}
						if expected, got := permissions, cert.Permissions.Extensions; !reflect.DeepEqual(got, expected) {
							return fmt.Errorf("incorrect Permissions.Extensions: expected: %#v actual: %#v", expected, got)
						}

						criticalOptions := map[string]string{
							"permit-port-forwarding": "",
							"permit-pty":             "",
						}
						if expected, got := criticalOptions, cert.Permissions.CriticalOptions; !reflect.DeepEqual(got, expected) {
							return fmt.Errorf("incorrect Permissions.CriticalOptions: expected: %#v actual: %#v", expected, got)
						}
						return nil
					}),
				),
			},
		},
	})
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
