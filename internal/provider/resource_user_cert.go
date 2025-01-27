// Copyright (c) HashiCorp, Inc.

package provider

import (
	"context"
	"golang.org/x/crypto/ssh"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &userCertResource{}
var _ resource.ResourceWithImportState = &userCertResource{}

func NewUserCertResource() resource.Resource {
	r := &userCertResource{}
	r.certType = ssh.UserCert
	return r
}

type userCertResource struct {
	commonCert
}

func (r *userCertResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user_cert"
}
