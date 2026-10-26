// Copyright 2026 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package logs

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
)

// MaskAction is the effective action the decision log masking policy takes on
// a field of a decision log event.
type MaskAction string

const (
	// MaskActionRetain keeps the field unchanged in the logged event.
	MaskActionRetain MaskAction = "retain"

	// MaskActionHash replaces the field value with a digest computed by
	// [topdown.MaskingHash] (SHA-256, or HMAC-SHA256 when the rule sets a key).
	MaskActionHash MaskAction = "hash"

	// MaskActionRemove erases the field from the logged event.
	MaskActionRemove MaskAction = "remove"

	// MaskActionUpsert replaces the field value with a fixed value provided by
	// the masking policy. It is reported for backwards-compatible "upsert"
	// rules.
	MaskActionUpsert MaskAction = "upsert"
)

// DefaultMaskAction is the secure-by-default action assigned to event fields
// that no masking rule covers. Removing an uncovered field can never leak data
// that the policy author did not explicitly classify.
const DefaultMaskAction = MaskActionRemove

// PreviewMaskOptions parameterizes [Plugin.PreviewMask].
type PreviewMaskOptions struct {
	// Event is a sample decision log event evaluated against the masking
	// policy, the same way an event handed to Log would be. It is never
	// modified, buffered, uploaded, or otherwise written to a log sink.
	Event *EventV1

	// DefaultAction classifies event fields that no masking rule covers. It
	// must be one of MaskActionRetain, MaskActionHash, or MaskActionRemove.
	// When unset, DefaultMaskAction (remove) is used.
	DefaultAction MaskAction
}

// MaskPathVerdict describes what happens to a single JSON Pointer path of the
// sample event when it is logged.
type MaskPathVerdict struct {
	// Path is the JSON Pointer of the event field, e.g. /input/users/0/ssn.
	Path string `json:"path"`

	// Action is the effective action for the field.
	Action MaskAction `json:"action"`

	// Matched reports whether a masking rule covered the path. When false,
	// Action is the preview's default action.
	Matched bool `json:"matched"`

	// RuleIndex is the index of the matching rule in MaskPreview.Rules, when
	// Matched is true.
	RuleIndex int `json:"rule_index,omitempty"`

	// Reason explains why the action was chosen.
	Reason string `json:"reason"`
}

// MaskRulePreview describes a single rule returned by the masking policy.
type MaskRulePreview struct {
	// Index is the position of the rule in the policy result, rules applying
	// in that order.
	Index int `json:"index"`

	// Op is the operation the rule performs (remove, hash, retain, or upsert).
	Op MaskAction `json:"op"`

	// Path is the JSON Pointer the rule targets.
	Path string `json:"path"`

	// Present reports whether the rule's path exists in the sample event. A
	// false value for remove/hash/retain rules means the rule is a no-op for
	// this event; upsert rules with a false value create the targeted field.
	Present bool `json:"present"`
}

// MaskPreview is the result of evaluating the masking policy against a sample
// event without logging anything.
type MaskPreview struct {
	// Decision is the data path of the masking decision that was evaluated.
	Decision string `json:"decision"`

	// DefaultAction is the action applied to fields no rule covers.
	DefaultAction MaskAction `json:"default_action"`

	// Bundles reports the revisions of the bundles associated with the sample
	// event, when the sample event carries bundle information.
	Bundles map[string]string `json:"bundles,omitempty"`

	// Rules are the masking rules the policy returned for the sample event.
	Rules []MaskRulePreview `json:"rules"`

	// Paths classifies every field of the sample event's input, result, and
	// nd_builtin_cache sections, including fields that would be created by
	// upsert rules.
	Paths []MaskPathVerdict `json:"paths"`
}

// PreviewMask evaluates the configured decision log masking policy against
// opts.Event and reports the retain/hash/remove (and upsert) classification of
// every event field, together with the reason each rule matched.
//
// The preview neither evaluates the logged decision nor writes to a log sink:
// no event is buffered, uploaded, printed to the console, or forwarded to a
// custom logger plugin. The masking policy is evaluated once on a read-only
// store transaction against a snapshot of the policy compiler, so a bundle
// updating while the preview runs cannot mix policy versions. Fields no rule
// matches are classified with the secure-by-default action (remove), unless
// opts.DefaultAction overrides it.
func (p *Plugin) PreviewMask(ctx context.Context, opts PreviewMaskOptions) (*MaskPreview, error) {
	if opts.Event == nil {
		return nil, errors.New("mask preview requires a sample event")
	}

	defaultAction := opts.DefaultAction
	if defaultAction == "" {
		defaultAction = DefaultMaskAction
	}

	switch defaultAction {
	case MaskActionRetain, MaskActionHash, MaskActionRemove:
	default:
		return nil, fmt.Errorf("invalid default mask action %q: expected %q, %q, or %q",
			defaultAction, MaskActionRetain, MaskActionHash, MaskActionRemove)
	}

	// Snapshot the configuration the same way the upload loop does, so that a
	// concurrent Reconfigure cannot race the preview.
	p.reconfigMtx.RLock()
	cfg := p.config
	p.reconfigMtx.RUnlock()

	store := p.manager.Store

	// One read transaction for policy data and evaluation; it is only aborted,
	// never committed.
	txn, err := store.NewTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Abort(ctx, txn)

	// Pin the compiler together with the transaction: both the prepared query
	// and the evaluation use this snapshot, so every returned rule comes from
	// the same policy version even if a bundle activates mid-preview.
	compiler := p.manager.GetCompiler()

	// Work on a shallow copy so building the event's AST does not cache a term
	// in the caller's event. The preview never mutates event data.
	sample := *opts.Event
	sample.inputAST = nil

	input, err := sample.AST()
	if err != nil {
		return nil, err
	}

	rules, err := p.evalMaskRulesForPreview(ctx, txn, compiler, &cfg, input)
	if err != nil {
		return nil, err
	}

	preview := &MaskPreview{
		Decision:      *cfg.MaskDecision,
		DefaultAction: defaultAction,
		Rules:         make([]MaskRulePreview, 0, len(rules)),
		Paths:         []MaskPathVerdict{},
	}

	if len(sample.Bundles) > 0 {
		preview.Bundles = make(map[string]string, len(sample.Bundles))
		for name, info := range sample.Bundles {
			preview.Bundles[name] = info.Revision
		}
	}

	roots := map[string]any{}
	if sample.Input != nil {
		roots[partInput] = *sample.Input
	}
	if sample.Result != nil {
		roots[partResult] = *sample.Result
	}
	if sample.NDBuiltinCache != nil {
		roots[partNDBCache] = *sample.NDBuiltinCache
	}

	for i, rule := range rules {
		preview.Rules = append(preview.Rules, MaskRulePreview{
			Index:   i,
			Op:      maskOPToAction(rule.OP),
			Path:    rule.String(),
			Present: pathExists(rule.escapedParts, roots),
		})
	}

	// Classify every field present in the sample event, roots first in a
	// fixed order for deterministic output.
	for _, name := range []string{partInput, partResult, partNDBCache} {
		root, ok := roots[name]
		if !ok {
			continue
		}

		walkMaskPath([]string{name}, root, func(parts []string, _ any) {
			preview.Paths = append(preview.Paths, classifyMaskPath(parts, rules, defaultAction))
		})
	}

	// Surface upsert rules that create fields absent from the sample.
	for i, rule := range rules {
		if rule.OP != maskOPUpsert || pathExists(rule.escapedParts, roots) {
			continue
		}

		preview.Paths = append(preview.Paths, MaskPathVerdict{
			Path:      rule.String(),
			Action:    MaskActionUpsert,
			Matched:   true,
			RuleIndex: i,
			Reason:    fmt.Sprintf("rule %d upserts a field that is absent from the sample event; the field would be created when logged", i),
		})
	}

	return preview, nil
}

// evalMaskRulesForPreview prepares and evaluates the masking decision against
// the pinned compiler and transaction. Print statements are disabled: the
// preview must not produce side effects through the manager's print hook.
func (p *Plugin) evalMaskRulesForPreview(ctx context.Context, txn storage.Transaction, compiler *ast.Compiler, cfg *Config, input ast.Value) ([]*maskRule, error) {
	query := ast.NewBody(ast.NewExpr(ast.NewTerm(cfg.maskDecisionRef)))

	r := rego.New(
		rego.ParsedQuery(query),
		rego.Compiler(compiler),
		rego.Store(p.manager.Store),
		rego.Transaction(txn),
		rego.Runtime(p.manager.Info),
		rego.EnablePrintStatements(false),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	rs, err := pq.Eval(
		ctx,
		rego.EvalParsedInput(input),
		rego.EvalTransaction(txn),
	)
	if err != nil {
		return nil, err
	} else if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}

	ruleSet, err := newMaskRuleSet(rs[0].Expressions[0].Value, func(*maskRule, error) {})
	if err != nil {
		return nil, err
	}

	return ruleSet.Rules, nil
}

func maskOPToAction(op maskOP) MaskAction {
	switch op {
	case maskOPHash:
		return MaskActionHash
	case maskOPRetain:
		return MaskActionRetain
	case maskOPUpsert:
		return MaskActionUpsert
	default:
		return MaskActionRemove
	}
}

// classifyMaskPath returns the verdict for one event path. When several rules
// cover the path, the last one in policy order wins, mirroring the sequential
// rule application performed when an event is logged.
func classifyMaskPath(parts []string, rules []*maskRule, defaultAction MaskAction) MaskPathVerdict {
	path := "/" + strings.Join(parts, "/")

	for i := len(rules) - 1; i >= 0; i-- {
		rule := rules[i]

		if !ruleCoversPath(rule.escapedParts, parts) {
			continue
		}

		action := maskOPToAction(rule.OP)
		reason := fmt.Sprintf("matched rule %d (op %q) exactly", i, action)

		if len(rule.escapedParts) < len(parts) {
			reason = fmt.Sprintf("inherited from rule %d (op %q) on %s, the most specific covering rule",
				i, action, rule.String())
		}

		return MaskPathVerdict{
			Path:      path,
			Action:    action,
			Matched:   true,
			RuleIndex: i,
			Reason:    reason,
		}
	}

	return MaskPathVerdict{
		Path:    path,
		Action:  defaultAction,
		Matched: false,
		Reason:  fmt.Sprintf("no masking rule matched; applying secure-by-default action %q", defaultAction),
	}
}

// ruleCoversPath reports whether a rule at ruleParts applies to a field at
// nodeParts: the rule path must be an ancestor of, or equal to, the field
// path, on path segment boundaries.
func ruleCoversPath(ruleParts, nodeParts []string) bool {
	if len(ruleParts) > len(nodeParts) {
		return false
	}

	for i := range ruleParts {
		if ruleParts[i] != nodeParts[i] {
			return false
		}
	}

	return true
}

// pathExists reports whether the rule's target path is present in the sample
// event roots.
func pathExists(ruleParts []string, roots map[string]any) bool {
	root, ok := roots[ruleParts[0]]
	if !ok {
		return false
	}

	if len(ruleParts) == 1 {
		return true
	}

	node := root

	for _, part := range ruleParts[1:] {
		switch v := node.(type) {
		case map[string]any:
			// Look up the unescaped component: escapedParts stores URL-escaped
			// segments, and event maps carry the raw keys.
			child, ok := v[unescapeMaskPart(part)]
			if !ok {
				return false
			}
			node = child

		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(v) {
				return false
			}
			node = v[index]

		default:
			return false
		}
	}

	return true
}

func unescapeMaskPart(part string) string {
	if v, err := url.PathUnescape(part); err == nil {
		return v
	}

	return part
}

// walkMaskPath visits a node and all of its descendants depth-first. Object
// keys are visited in sorted order and array elements in index order; path
// segments are escaped the same way mask rule paths are so they compare
// directly.
func walkMaskPath(parts []string, node any, visit func([]string, any)) {
	visit(parts, node)

	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)

		for _, k := range keys {
			walkMaskPath(append(append([]string{}, parts...), url.PathEscape(k)), v[k], visit)
		}

	case []any:
		for i, child := range v {
			walkMaskPath(append(append([]string{}, parts...), strconv.Itoa(i)), child, visit)
		}
	}
}
