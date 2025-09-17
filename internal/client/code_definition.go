package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/zgsm-ai/chat-rag/internal/config"
	"github.com/zgsm-ai/chat-rag/internal/types"
)

// DefinitionInterface defines the interface for code definition search client
type DefinitionInterface interface {
	// Search performs code definition search and returns definition details
	Search(ctx context.Context, req DefinitionRequest) (string, error)
	// CheckReady checks if the code definition search service is available
	CheckReady(ctx context.Context, req ReadyRequest) (bool, error)
}

// DefinitionRequest represents the request structure for code definition search
type DefinitionRequest struct {
	ClientId      string `json:"clientId"`
	CodebasePath  string `json:"codebasePath"`
	FilePath      string `json:"filePath,omitempty"`
	StartLine     *int   `json:"startLine,omitempty"`
	EndLine       *int   `json:"endLine,omitempty"`
	SymbolName    string `json:"symbolName,omitempty"`
	Authorization string `json:"authorization"`
	ClientVersion string `json:"clientVersion"`
}

// DefinitionResponseWrapper represents the API standard response wrapper for code definition search
type DefinitionResponseWrapper struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    *DefinitionData `json:"data"`
}

// DefinitionData wraps the actual code definition search results
type DefinitionData struct {
	Results []DefinitionResult `json:"list"`
}

// DefinitionResult represents a single code definition search result
type DefinitionResult struct {
	FilePath string             `json:"filePath"`
	Name     string             `json:"name"`
	Type     string             `json:"type"`
	Content  string             `json:"content"`
	Position DefinitionPosition `json:"position"`
}

// DefinitionPosition represents the position information of a definition
type DefinitionPosition struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

// DefinitionClient handles communication with the code definition search service
type DefinitionClient struct {
	*BaseClient[DefinitionRequest, string]
}

// NewDefinitionClient creates a new definition client instance
func NewDefinitionClient(definitionConfig config.DefinitionSearchConfig) DefinitionInterface {
	config := BaseClientConfig{
		SearchEndpoint: definitionConfig.SearchEndpoint,
		ReadyEndpoint:  definitionConfig.ApiReadyEndpoint,
		SearchTimeout:  5 * time.Second,
		ReadyTimeout:   5 * time.Second,
	}

	baseClient := NewBaseClient(config,
		&DefinitionRequestBuilder{},
		&DefinitionRequestBuilder{},
		&StringResponseHandler{},
		&StringResponseHandler{},
	)

	return &DefinitionClient{
		BaseClient: baseClient,
	}
}

// Search performs code definition search and returns definition details
func (c *DefinitionClient) Search(ctx context.Context, req DefinitionRequest) (string, error) {
	return c.BaseClient.Search(ctx, req)
}

// CheckReady checks if the code definition search service is available
func (c *DefinitionClient) CheckReady(ctx context.Context, req ReadyRequest) (bool, error) {
	return c.BaseClient.CheckReady(ctx, req)
}

// DefinitionRequestBuilder Definition请求构建策略
type DefinitionRequestBuilder struct{}

func (b *DefinitionRequestBuilder) BuildRequest(req DefinitionRequest) Request {
	queryParams := map[string]string{
		"clientId":     req.ClientId,
		"codebasePath": req.CodebasePath,
	}

	// 根据查询方式添加参数
	if req.SymbolName != "" {
		queryParams["symbolName"] = req.SymbolName
	} else {
		// 使用文件路径和行号方式查询
		if req.FilePath != "" {
			queryParams["filePath"] = req.FilePath
		}
		if req.StartLine != nil {
			queryParams["startLine"] = fmt.Sprintf("%d", *req.StartLine)
		}
		if req.EndLine != nil {
			queryParams["endLine"] = fmt.Sprintf("%d", *req.EndLine)
		}
	}

	return Request{
		Headers: map[string]string{
			types.HeaderClientVersion: req.ClientVersion,
		},
		Method:        http.MethodGet,
		QueryParams:   queryParams,
		Authorization: req.Authorization,
	}
}

func (b *DefinitionRequestBuilder) BuildReadyRequest(req ReadyRequest) Request {
	return Request{
		Headers: map[string]string{
			types.HeaderClientVersion: req.ClientVersion,
		},
		Method: http.MethodGet,
		QueryParams: map[string]string{
			"clientId":     req.ClientId,
			"codebasePath": req.CodebasePath,
		},
		Authorization: req.Authorization,
	}
}
