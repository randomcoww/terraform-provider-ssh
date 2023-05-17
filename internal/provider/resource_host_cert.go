package provider

import (
	"context"
	"golang.org/x/crypto/ssh"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &hostCertResource{}
var _ resource.ResourceWithImportState = &hostCertResource{}

func NewHostCertResource() resource.Resource {
	r := &hostCertResource{}
	r.certType = ssh.HostCert
	return r
}

type hostCertResource struct {
	commonCert
}

func (r *hostCertResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host_cert"
}
