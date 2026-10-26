// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Deprecated: This package is intended for older projects transitioning from OPA v0.x and will remain for the lifetime of OPA v1.x, but its use is not recommended.
// For newer features and behaviours, such as defaulting to the Rego v1 syntax, use the corresponding components in the [github.com/open-policy-agent/opa/v1] package instead.
// See https://www.openpolicyagent.org/docs/latest/v0-compatibility/ for more information.
//
// Package logs implements decision log buffering and uploading.
package logs

import (
	"github.com/open-policy-agent/opa/plugins"
	v1 "github.com/open-policy-agent/opa/v1/plugins/logs"
)

// Logger defines the interface for decision logging plugins.
type Logger = v1.Logger

// EventV1 represents a decision log event.
// WARNING: The AST() function for EventV1 must be kept in sync with
// the struct. Any changes here MUST be reflected in the AST()
// implementation below.
type EventV1 = v1.EventV1

// BundleInfoV1 describes a bundle associated with a decision log event.
type BundleInfoV1 = v1.BundleInfoV1

type RequestContext = v1.RequestContext

type HTTPRequestContext = v1.HTTPRequestContext

// ReportingConfig represents configuration for the plugin's reporting behaviour.
type ReportingConfig = v1.ReportingConfig

type RequestContextConfig = v1.RequestContextConfig

type HTTPRequestContextConfig = v1.HTTPRequestContextConfig

// Config represents the plugin configuration.
type Config = v1.Config

// Plugin implements decision log buffering and uploading.
type Plugin = v1.Plugin

func ParseConfig(config []byte, services []string, pluginList []string) (*Config, error) {
	return v1.ParseConfig(config, services, pluginList)
}

// ConfigBuilder assists in the construction of the plugin configuration.
type ConfigBuilder = v1.ConfigBuilder

// NewConfigBuilder returns a new ConfigBuilder to build and parse the plugin config.
func NewConfigBuilder() *ConfigBuilder {
	return v1.NewConfigBuilder()
}

// New returns a new Plugin with the given config.
func New(parsedConfig *Config, manager *plugins.Manager) *Plugin {
	return v1.New(parsedConfig, manager)
}

// Name identifies the plugin on manager.
const Name = v1.Name

// Lookup returns the decision logs plugin registered with the manager.
func Lookup(manager *plugins.Manager) *Plugin {
	return v1.Lookup(manager)
}

// MaskAction is the effective action the masking policy takes on an event
// field.
type MaskAction = v1.MaskAction

// Mask actions reported by a masking policy preview.
const (
	MaskActionRetain = v1.MaskActionRetain
	MaskActionHash   = v1.MaskActionHash
	MaskActionRemove = v1.MaskActionRemove
	MaskActionUpsert = v1.MaskActionUpsert

	// DefaultMaskAction is the secure-by-default action for fields that no
	// masking rule covers.
	DefaultMaskAction = v1.DefaultMaskAction
)

// PreviewMaskOptions parameterizes a masking policy preview.
type PreviewMaskOptions = v1.PreviewMaskOptions

// MaskPathVerdict describes what happens to a single field when logged.
type MaskPathVerdict = v1.MaskPathVerdict

// MaskRulePreview describes one rule returned by the masking policy.
type MaskRulePreview = v1.MaskRulePreview

// MaskPreview is the result of previewing the masking policy on a sample
// event without logging it.
type MaskPreview = v1.MaskPreview
