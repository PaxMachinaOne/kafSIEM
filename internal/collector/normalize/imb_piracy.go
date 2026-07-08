// Copyright 2024 ff, Scalytics, Inc. - https://www.scalytics.io
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"strings"

	"github.com/scalytics/kafSIEM/internal/collector/model"
	"github.com/scalytics/kafSIEM/internal/collector/parse"
)

func IMBPiracyAlert(ctx Context, meta model.RegistrySource, item parse.FeedItem) *model.Alert {
	alert := baseAlert(ctx, meta, item.Title, item.Link, item.Summary, ctx.Now)
	alert.Category = "maritime_security"
	alert.Severity = "high"
	if strings.Contains(strings.ToLower(item.Summary), "kidnap") ||
		strings.Contains(strings.ToLower(item.Summary), "hijack") ||
		strings.Contains(strings.ToLower(item.Summary), "houthi") {
		alert.Severity = "critical"
	}
	alert.Triage = score(ctx.Config, alert, FeedContext{
		Summary:  item.Summary,
		Tags:     item.Tags,
		FeedType: meta.Type,
	})
	assignSubcategory(&alert, item.Summary, item.Title)
	return &alert
}