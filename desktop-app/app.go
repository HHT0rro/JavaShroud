package main

import (
	"context"
	"encoding/json"
	"sync"
)

const engineEventName = "engine:event"

type ObfuscationRequest struct {
	InputJarPath         string     `json:"inputJarPath"`
	OutputJarPath        string     `json:"outputJarPath"`
	Passes               []PassSpec `json:"passes"`
	Rules                []RuleItem `json:"rules"`
	AllowOptInPasses     bool       `json:"allowOptInPasses"`
	AllowRedundantPasses bool       `json:"allowRedundantPasses"`
}

type PassSpec struct {
	ID      string                     `json:"id"`
	Enabled bool                       `json:"enabled"`
	Params  map[string]json.RawMessage `json:"params"`
}

type RuleItem struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Action string `json:"action"`
}

type EngineConfig struct {
	InputJarPath         string     `json:"inputJarPath"`
	OutputJarPath        string     `json:"outputJarPath"`
	Passes               []PassSpec `json:"passes"`
	RuleSet              RuleSet    `json:"ruleSet"`
	AllowOptInPasses     bool       `json:"allowOptInPasses"`
	AllowRedundantPasses bool       `json:"allowRedundantPasses"`
}

type RuleSet struct {
	Rules []RuleItem `json:"rules"`
}

type EngineEvent struct {
	Level    string  `json:"level"`
	Type     string  `json:"type"`
	Message  string  `json:"message"`
	Progress *int    `json:"progress"`
	OutPath  *string `json:"outPath"`
}

type EngineLaunchSpec struct {
	CommandPath string
	CommandArgs []string
	CommandDir  string
	Mode        string
}

type App struct {
	ctx           context.Context
	cancelCurrent context.CancelFunc
	mu            sync.Mutex
}

func NewApp() *App {
	return &App{}
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
}
