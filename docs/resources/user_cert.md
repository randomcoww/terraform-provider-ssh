---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ssh_user_cert Resource - ssh"
subcategory: ""
description: |-
  Create SSH certificate
---

# ssh_user_cert (Resource)

Create SSH certificate



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `ca_private_key_pem` (String, Sensitive) Private key of the Certificate Authority (CA) used to sign the certificate, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.
- `critical_options` (List of String) List of critical options for certificate usage permissions.
- `extensions` (List of String) List of extensions for certificate usage permissions.
- `key_id` (String) User or host identifier for certificate.
- `public_key_openssh` (String) SSH public key to sign, in authorized keys format.
- `valid_principals` (List of String) List of hostnames to use as subjects of the certificate.
- `validity_period_hours` (Number) Number of hours, after initial issuing, that the certificate will remain valid for.

### Optional

- `early_renewal_hours` (Number) The resource will consider the certificate to have expired the given number of hours before its actual expiry time. This can be useful to deploy an updated certificate in advance of the expiration of the current certificate. However, the old certificate remains valid until its true expiration time, since this resource does not (and cannot) support certificate revocation. Also, this advance update can only be performed should the Terraform configuration be applied during the early renewal period. (default: `0`)

### Read-Only

- `ca_key_algorithm` (String) Name of the algorithm used when generating the private key provided in `ca_private_key_pem`.
- `cert_authorized_key` (String) Signed SSH certificate.
- `id` (String) Unique identifier for this resource: the certificate serial number.
- `ready_for_renewal` (Boolean) Is the certificate either expired (i.e. beyond the `validity_period_hours`) or ready for an early renewal (i.e. within the `early_renewal_hours`)?
- `validity_end_time` (String) The time until which the certificate is invalid, expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.
- `validity_start_time` (String) The time after which the certificate is valid, expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.
