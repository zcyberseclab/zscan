package stage

import "strings"

type PluginType string

const (
	PluginTypeAuth PluginType = "auth"
)

type PluginContext struct {
	Target  TargetSpec
	Service ServiceInfo
}

type Plugin interface {
	Name() string
	Type() PluginType
	Supports(ctx PluginContext) bool
	Execute(ctx PluginContext) []AuthEvent
}

type PluginRegistry struct {
	plugins []Plugin
}

func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{plugins: make([]Plugin, 0)}
}

func (r *PluginRegistry) Register(p Plugin) {
	if p == nil {
		return
	}
	r.plugins = append(r.plugins, p)
}

func (r *PluginRegistry) RunAuthPlugins(ctx PluginContext) []AuthEvent {
	events := make([]AuthEvent, 0)
	for _, p := range r.plugins {
		if p.Type() != PluginTypeAuth || !p.Supports(ctx) {
			continue
		}
		events = append(events, p.Execute(ctx)...)
	}
	return events
}

// AuthFrameworkReadyPlugin is a minimal plugin to validate auth pipeline wiring.
type AuthFrameworkReadyPlugin struct{}

func (p *AuthFrameworkReadyPlugin) Name() string { return "auth-framework-ready" }
func (p *AuthFrameworkReadyPlugin) Type() PluginType {
	return PluginTypeAuth
}

func (p *AuthFrameworkReadyPlugin) Supports(ctx PluginContext) bool {
	for _, t := range ctx.Service.Types {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "ssh", "redis", "mysql", "postgresql", "ftp":
			return true
		}
	}
	return false
}

func (p *AuthFrameworkReadyPlugin) Execute(ctx PluginContext) []AuthEvent {
	serviceName := "unknown"
	for _, t := range ctx.Service.Types {
		if v := strings.ToLower(strings.TrimSpace(t)); v != "" {
			serviceName = v
			break
		}
	}
	return []AuthEvent{{
		Service:  serviceName,
		Result:   "not_attempted",
		Evidence: "auth plugin framework connected",
	}}
}
