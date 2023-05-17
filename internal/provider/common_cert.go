// https://github.com/hashicorp/terraform-provider-tls/blob/main/internal/provider/common_cert.go

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

func modifyPlanIfCertificateReadyForRenewal(ctx context.Context, req *resource.ModifyPlanRequest, res *resource.ModifyPlanResponse) {
	// Retrieve `validity_end_time` and confirm is a known, non-null value
	validityEndTimePath := path.Root("validity_end_time")
	var validityEndTimeStr types.String
	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, validityEndTimePath, &validityEndTimeStr)...)
	if res.Diagnostics.HasError() {
		return
	}
	if validityEndTimeStr.IsNull() || validityEndTimeStr.IsUnknown() {
		return
	}

	// Parse `validity_end_time`
	validityEndTime, err := time.Parse(time.RFC3339, validityEndTimeStr.ValueString())
	if err != nil {
		res.Diagnostics.AddError(
			fmt.Sprintf("Failed to parse data from string: %s", validityEndTimeStr.ValueString()),
			err.Error(),
		)
		return
	}

	// Retrieve `early_renewal_hours`
	earlyRenewalHoursPath := path.Root("early_renewal_hours")
	var earlyRenewalHours int64
	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, earlyRenewalHoursPath, &earlyRenewalHours)...)
	if res.Diagnostics.HasError() {
		return
	}

	currentTime := overridableTimeFunc()

	// Determine the time from which an "early renewal" is possible
	earlyRenewalPeriod := time.Duration(-earlyRenewalHours) * time.Hour
	earlyRenewalTime := validityEndTime.Add(earlyRenewalPeriod)

	// If "early renewal" time has passed, mark it "ready for renewal"
	timeToEarlyRenewal := earlyRenewalTime.Sub(currentTime)
	if timeToEarlyRenewal <= 0 {
		tflog.Info(ctx, "Certificate is ready for early renewal")
		readyForRenewalPath := path.Root("ready_for_renewal")
		res.Diagnostics.Append(res.Plan.SetAttribute(ctx, readyForRenewalPath, types.BoolUnknown())...)
		res.RequiresReplace = append(res.RequiresReplace, readyForRenewalPath)
	}
}

func modifyStateIfCertificateReadyForRenewal(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Retrieve `validity_end_time` and confirm is a known, non-null value
	validityEndTimePath := path.Root("validity_end_time")
	var validityEndTimeStr types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, validityEndTimePath, &validityEndTimeStr)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if validityEndTimeStr.IsNull() || validityEndTimeStr.IsUnknown() {
		return
	}

	// Parse `validity_end_time`
	validityEndTime, err := time.Parse(time.RFC3339, validityEndTimeStr.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Failed to parse data from string: %s", validityEndTimeStr.ValueString()),
			err.Error(),
		)
		return
	}

	// Retrieve `early_renewal_hours`
	earlyRenewalHoursPath := path.Root("early_renewal_hours")
	var earlyRenewalHours int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, earlyRenewalHoursPath, &earlyRenewalHours)...)
	if resp.Diagnostics.HasError() {
		return
	}

	currentTime := overridableTimeFunc()

	// Determine the time from which an "early renewal" is possible
	earlyRenewalPeriod := time.Duration(-earlyRenewalHours) * time.Hour
	earlyRenewalTime := validityEndTime.Add(earlyRenewalPeriod)

	// If "early renewal" time has passed, mark it "ready for renewal"
	timeToEarlyRenewal := earlyRenewalTime.Sub(currentTime)
	if timeToEarlyRenewal <= 0 {
		tflog.Info(ctx, "Certificate is ready for early renewal")
		readyForRenewalPath := path.Root("ready_for_renewal")
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, readyForRenewalPath, true)...)
	}
}
