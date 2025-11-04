package config

// ParameterSource Parameter source enumeration
type ParameterSource string

const (
	ParameterSourceLLM    ParameterSource = "llm"    // Extract from LLM response, LLM must provide XML format
	ParameterSourceManual ParameterSource = "manual" // Manual setting, get from default field in config file
)

// ParameterType Parameter type enumeration
type ParameterType string

const (
	ParameterTypeString  ParameterType = "string"
	ParameterTypeInteger ParameterType = "integer"
	ParameterTypeFloat   ParameterType = "float"
	ParameterTypeBoolean ParameterType = "boolean"
	ParameterTypeArray   ParameterType = "array"
)

// LLMConfig
type LLMConfig struct {
	Endpoint          string
	FuncCallingModels []string
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type ToolConfig struct {
	// Global switch to control whether all tools are disabled, default is false
	DisableTools bool
	// Control which agents in which modes cannot use tools
	DisabledAgents map[string][]string

	// Generic tool configuration
	GenericTools []GenericToolConfig
}

// GenericToolConfig Generic tool configuration structure
type GenericToolConfig struct {
	Name        string                 `yaml:"name"`        // Tool name
	Description string                 `yaml:"description"` // Tool description
	Capability  string                 `yaml:"capability"`  // Tool capability description
	Endpoints   GenericToolEndpoints   `yaml:"endpoints"`   // API endpoint configuration
	Method      string                 `yaml:"method"`      // HTTP request method
	Parameters  []GenericToolParameter `yaml:"parameters"`  // Parameter definitions
	Rule        string                 `yaml:"rule"`        // Tool usage rules
}

// GenericToolEndpoints Tool endpoint configuration
type GenericToolEndpoints struct {
	Search string `yaml:"search"` // Search endpoint
	Ready  string `yaml:"ready"`  // Readiness check endpoint
}

// GenericToolParameter Tool parameter definition
type GenericToolParameter struct {
	Name        string      `yaml:"name"`        // Parameter name
	Type        string      `yaml:"type"`        // Parameter type
	Description string      `yaml:"description"` // Parameter description
	Required    bool        `yaml:"required"`    // Whether required
	Default     interface{} `yaml:"default"`     // Default value
	// Parameter source
	Source ParameterSource `yaml:"source"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	LogFilePath          string
	LogScanIntervalSec   int
	ClassifyModel        string
	EnableClassification bool
}

type ContextCompressConfig struct {
	// Context compression enable flag
	EnableCompress bool
	// Context compression token threshold
	TokenThreshold int
	// Summary Model configuration
	SummaryModel               string
	SummaryModelTokenThreshold int
	// used recent user prompt messages nums
	RecentUserMsgUsedNums int
}

type PreciseContextConfig struct {
	// AgentsMatch configuration
	AgentsMatch []AgentMatchConfig
	// filter "environment_details" user prompt in context
	EnableEnvDetailsFilter bool
	// Control which agents in which modes cannot use ModesChange
	DisabledModesChangeAgents map[string][]string
}

// AgentMatchConfig holds configuration for a specific agent matching
type AgentMatchConfig struct {
	Agent string `yaml:"agent"`
	Key   string `yaml:"key"`
}

// Config holds all service configuration
type Config struct {
	// Server configuration
	Host string
	Port int

	// Tools configuration
	Tools ToolConfig

	// Logging configuration
	Log LogConfig

	// Context handling configuration
	ContextCompressConfig ContextCompressConfig
	PreciseContextConfig  PreciseContextConfig

	//Department configuration
	DepartmentApiEndpoint string

	// Redis configuration
	Redis RedisConfig

	LLM LLMConfig
}

// AgentConfig holds configuration for a specific agent
type AgentConfig struct {
	MatchAgents []string `mapstructure:"match_agents"`
	MatchModes  []string `mapstructure:"match_modes"`
	Rules       string   `mapstructure:"rules"`
}

// RulesConfig holds the rules configuration for agents
type RulesConfig struct {
	Agents []AgentConfig `yaml:"agents"`
}
