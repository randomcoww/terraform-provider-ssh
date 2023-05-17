package provider

import (
	"context"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"
	"math/big"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// commonCert defines the resource implementation.
type commonCert struct {
	certType uint32
}

// commonCertModel describes the resource data model.
type commonCertModel struct {
	CAPrivateKeyPEM     types.String `tfsdk:"ca_private_key_pem"`
	PublicKeyOpenSSH    types.String `tfsdk:"public_key_openssh"`
	ValidityPeriodHours types.Int64  `tfsdk:"validity_period_hours"`
	KeyID               types.String `tfsdk:"key_id"`
	ValidPrincipals     types.List   `tfsdk:"valid_principals"`
	CriticalOptions     types.List   `tfsdk:"critical_options"`
	Extensions          types.List   `tfsdk:"extensions"`
	EarlyRenewalHours   types.Int64  `tfsdk:"early_renewal_hours"`
	ValidityStartTime   types.String `tfsdk:"validity_start_time"`
	ValidityEndTime     types.String `tfsdk:"validity_end_time"`
	CAKeyAlgorithm      types.String `tfsdk:"ca_key_algorithm"`
	CertAuthorizedKey   types.String `tfsdk:"cert_authorized_key"`
	ID                  types.String `tfsdk:"id"`
}

func (r *commonCert) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Create SSH certificate",

		Attributes: map[string]schema.Attribute{
			"ca_private_key_pem": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					requireReplaceIfStateContainsPEMString(),
				},
				Sensitive: true,
				Description: "Private key of the Certificate Authority (CA) used to sign the certificate, " +
					"in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
			},
			"public_key_openssh": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "SSH public key to sign, " +
					"in authorized keys format.",
			},
			"validity_period_hours": schema.Int64Attribute{
				Required: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
				Description: "Number of hours, after initial issuing, that the certificate will remain valid for.",
			},
			"key_id": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "User or host identifier for certificate.",
			},
			"valid_principals": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
				Description: "List of hostnames to use as subjects of the certificate.",
			},
			"critical_options": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
				Description: "List of critical options for certificate usage permissions.",
			},
			"extensions": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
				Description: "List of extensions for certificate usage permissions.",
			},

			// Optional
			"early_renewal_hours": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
				Validators: []validator.Int64{
					int64validator.AtLeast(0),
				},
				Description: "The resource will consider the certificate to have expired the given number of hours " +
					"before its actual expiry time. This can be useful to deploy an updated certificate in advance of " +
					"the expiration of the current certificate. " +
					"However, the old certificate remains valid until its true expiration time, since this resource " +
					"does not (and cannot) support certificate revocation. " +
					"Also, this advance update can only be performed should the Terraform configuration be applied " +
					"during the early renewal period. (default: `0`)",
			},
			// "ready_for_renewal": schema.BoolAttribute{
			// 	Computed: true,
			// 	Default:  booldefault.StaticBool(false),
			// 	PlanModifiers: []planmodifier.Bool{
			// 		attribute_plan_modifier_bool.ReadyForRenewal(),
			// 	},
			// 	Description: "Is the certificate either expired (i.e. beyond the `validity_period_hours`) " +
			// 		"or ready for an early renewal (i.e. within the `early_renewal_hours`)?",
			// },
			"validity_start_time": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The time after which the certificate is valid, " +
					"expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
			},
			"validity_end_time": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The time until which the certificate is invalid, " +
					"expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
			},
			"ca_key_algorithm": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Name of the algorithm used when generating the private key provided in `ca_private_key_pem`. ",
			},
			"cert_authorized_key": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Signed SSH certificate.",
			},
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Unique identifier for this resource: the certificate serial number.",
			},
		},
	}
}

func (r *commonCert) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
}

func (r *commonCert) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var newState commonCertModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &newState)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certificate, diags := baseCertificate(ctx, &req.Plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	certificate.CertType = r.certType

	caPrvKey, algorithm, err := parsePrivateKeyPEM([]byte(newState.CAPrivateKeyPEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Failed to parse CA private key PEM", err.Error())
		return
	}
	signer, err := ssh.NewSignerFromKey(caPrvKey)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create signer with private key", err.Error())
		return
	}
	newState.CAKeyAlgorithm = types.StringValue(algorithm.String())

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(newState.PublicKeyOpenSSH.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Failed to marshal public key error", err.Error())
		return
	}
	certificate.Key = pubKey

	if err := certificate.SignCert(rand.Reader, signer); err != nil {
		resp.Diagnostics.AddError("Failed sign cert", err.Error())
		return
	}

	validFromBytes, err := time.Unix(int64(certificate.ValidAfter), 0).MarshalText()
	if err != nil {
		resp.Diagnostics.AddError("Failed to serialize validity start time", err.Error())
		return
	}
	validToBytes, err := time.Unix(int64(certificate.ValidBefore), 0).MarshalText()
	if err != nil {
		resp.Diagnostics.AddError("Failed to serialize validity end time", err.Error())
		return
	}

	newState.ID = types.StringValue(fmt.Sprintf("%d", certificate.Serial))
	newState.CertAuthorizedKey = types.StringValue(string(ssh.MarshalAuthorizedKey(certificate)))
	newState.ValidityStartTime = types.StringValue(string(validFromBytes))
	newState.ValidityEndTime = types.StringValue(string(validToBytes))
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

func (r *commonCert) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	modifyStateIfCertificateReadyForRenewal(ctx, req, resp)
}

func (r *commonCert) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	updatedUsingPlan(ctx, &req, resp, &commonCertModel{})
}

func (r *commonCert) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (r *commonCert) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *commonCert) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, res *resource.ModifyPlanResponse) {
	modifyPlanIfCertificateReadyForRenewal(ctx, &req, res)
}

func baseCertificate(ctx context.Context, plan *tfsdk.Plan) (*ssh.Certificate, diag.Diagnostics) {
	var diags diag.Diagnostics
	template := &ssh.Certificate{
		Permissions: ssh.Permissions{
			CriticalOptions: make(map[string]string),
			Extensions:      make(map[string]string),
		},
	}

	var keyID string
	diags.Append(plan.GetAttribute(ctx, path.Root("key_id"), &keyID)...)
	if diags.HasError() {
		return nil, diags
	}
	template.KeyId = keyID

	var validityPeriodHours int64
	diags.Append(plan.GetAttribute(ctx, path.Root("validity_period_hours"), &validityPeriodHours)...)
	if diags.HasError() {
		return nil, diags
	}
	now := overridableTimeFunc()
	template.ValidAfter = uint64(now.Unix())
	template.ValidBefore = uint64(now.Add(time.Duration(validityPeriodHours) * time.Hour).Unix())

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		diags.AddError("Failed to generate serial number", err.Error())
		return nil, diags
	}
	template.Serial = serial.Uint64()

	var validPrincipals types.List
	diags.Append(plan.GetAttribute(ctx, path.Root("valid_principals"), &validPrincipals)...)
	if diags.HasError() {
		return nil, diags
	}
	if !validPrincipals.IsNull() && !validPrincipals.IsUnknown() && len(validPrincipals.Elements()) > 0 {
		for _, v := range validPrincipals.Elements() {
			if vstr, ok := v.(types.String); ok {
				template.ValidPrincipals = append(template.ValidPrincipals, vstr.ValueString())
			}
		}
	}

	var criticalOptions types.List
	diags.Append(plan.GetAttribute(ctx, path.Root("critical_options"), &criticalOptions)...)
	if diags.HasError() {
		return nil, diags
	}
	if !criticalOptions.IsNull() && !criticalOptions.IsUnknown() && len(criticalOptions.Elements()) > 0 {
		for _, v := range criticalOptions.Elements() {
			if vstr, ok := v.(types.String); ok {
				template.Permissions.CriticalOptions[vstr.ValueString()] = ""
			}
		}
	}

	var extensions types.List
	diags.Append(plan.GetAttribute(ctx, path.Root("extensions"), &extensions)...)
	if diags.HasError() {
		return nil, diags
	}
	if !extensions.IsNull() && !extensions.IsUnknown() && len(extensions.Elements()) > 0 {
		for _, v := range extensions.Elements() {
			if vstr, ok := v.(types.String); ok {
				template.Permissions.Extensions[vstr.ValueString()] = ""
			}
		}
	}

	return template, nil
}
