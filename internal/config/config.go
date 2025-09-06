package config

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
	SemanticSearch   SemanticSearchConfig
	DefinitionSearch DefinitionSearchConfig
	ReferenceSearch  ReferenceSearchConfig
	KnowledgeSearch  KnowledgeSearchConfig
}

type SemanticSearchConfig struct {
	SearchEndpoint   string
	ApiReadyEndpoint string
	TopK             int
	ScoreThreshold   float64
}

type ReferenceSearchConfig struct {
	SearchEndpoint   string
	ApiReadyEndpoint string
}

type DefinitionSearchConfig struct {
	SearchEndpoint   string
	ApiReadyEndpoint string
}

type KnowledgeSearchConfig struct {
	SearchEndpoint   string
	ApiReadyEndpoint string
	TopK             int
	ScoreThreshold   float64
}

// LogConfig holds logging configuration
type LogConfig struct {
	LogFilePath          string
	LokiEndpoint         string
	LogScanIntervalSec   int
	EnableClassification bool
}

// Config holds all service configuration
type Config struct {
	// Server configuration
	Host string
	Port int

	// Token processing configuration
	TokenThreshold int

	// Tools configuration
	Tools ToolConfig

	// Logging configuration
	Log LogConfig

	// Model configuration
	SummaryModel               string
	SummaryModelTokenThreshold int
	ClassifyModel              string

	// used recent user prompt messages nums
	RecentUserMsgUsedNums int

	//Department configuration
	DepartmentApiEndpoint string

	// Redis configuration
	Redis RedisConfig

	LLM LLMConfig
}
