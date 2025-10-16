package logic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/zgsm-ai/chat-rag/internal/bootstrap"
	"github.com/zgsm-ai/chat-rag/internal/logger"
	"github.com/zgsm-ai/chat-rag/internal/model"
	"github.com/zgsm-ai/chat-rag/internal/tokenizer"
	"github.com/zgsm-ai/chat-rag/internal/types"
	"github.com/zgsm-ai/chat-rag/internal/utils"
	"go.uber.org/zap"
)

type ResponseHandler struct {
	ctx    context.Context
	svcCtx *bootstrap.ServiceContext
}

func NewResponseHandler(ctx context.Context, svcCtx *bootstrap.ServiceContext) *ResponseHandler {
	return &ResponseHandler{
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (h *ResponseHandler) extractResponseInfo(chatLog *model.ChatLog, response *types.ChatCompletionResponse) {
	logger.Info("extracting response info",
		zap.Int("choicesCount", len(response.Choices)),
	)

	// Extract response content from choices
	if len(response.Choices) > 0 {
		contentStr := utils.GetContentAsString(response.Choices[0].Message.Content)
		chatLog.ResponseContent = contentStr
	}

	// Extract usage information
	logger.Info("response usage",
		zap.Int("totalTokens", response.Usage.TotalTokens),
		zap.Int("promptTokens", response.Usage.PromptTokens),
		zap.Int("completionTokens", response.Usage.CompletionTokens),
	)

	if response.Usage.TotalTokens > 0 {
		chatLog.Usage = response.Usage
	} else {
		// Calculate usage if not provided
		chatLog.Usage = h.calculateUsage(chatLog.ProcessedTokens.All, chatLog.ResponseContent)
		logger.Info("calculated usage",
			zap.Int("totalTokens", chatLog.Usage.TotalTokens),
		)
	}
}

func (h *ResponseHandler) countTokens(text string) int {
	if h.svcCtx.TokenCounter != nil {
		return h.svcCtx.TokenCounter.CountTokens(text)
	}
	return tokenizer.EstimateTokens(text)
}

// calculateUsage calculates usage information when not provided by the model
func (h *ResponseHandler) calculateUsage(promptTokens int, responseContent string) types.Usage {
	completionTokens := h.countTokens(responseContent)
	return types.Usage{
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      promptTokens + completionTokens,
	}
}

// extractStreamingData extracts content and usage from streaming response lines
func (h *ResponseHandler) extractStreamingData(rawLine string) (content string, usage *types.Usage, response *types.ChatCompletionResponse) {
	// Skip non-data lines
	if !strings.HasPrefix(rawLine, "data: ") {
		return
	}

	// Extract JSON data
	jsonData := strings.TrimPrefix(rawLine, "data: ")
	if jsonData == "[DONE]" {
		content = jsonData
		return
	}

	// Parse streaming chunk
	var chunk map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &chunk); err != nil {
		logger.Error("failed to parse streaming chunk",
			zap.Error(err),
			zap.String("data", jsonData),
		)
		return
	}

	if choices, ok := chunk["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if delta, ok := choice["delta"].(map[string]interface{}); ok {
				if c, ok := delta["content"].(string); ok {
					content = c
				}
			}
		}
	}
	// 提取元数据
	response = &types.ChatCompletionResponse{}
	if id, ok := chunk["id"].(string); ok {
		response.Id = id
	}
	if object, ok := chunk["object"].(string); ok {
		response.Object = object
	}
	if created, ok := chunk["created"].(float64); ok {
		response.Created = int64(created)
	}
	if model, ok := chunk["model"].(string); ok {
		response.Model = model
	}

	// 提取用量信息
	if usageData, ok := chunk["usage"].(map[string]interface{}); ok {
		usage = &types.Usage{}
		if promptTokens, ok := usageData["prompt_tokens"].(float64); ok {
			usage.PromptTokens = int(promptTokens)
		}
		if completionTokens, ok := usageData["completion_tokens"].(float64); ok {
			usage.CompletionTokens = int(completionTokens)
		}
		if totalTokens, ok := usageData["total_tokens"].(float64); ok {
			usage.TotalTokens = int(totalTokens)
		}
	}

	return
}

func (h *ResponseHandler) CreateSSEData(finalResponse *types.ChatCompletionResponse, content string) string {
	finalResponse.Choices = []types.Choice{
		{
			Delta: types.Delta{
				Content: content,
			},
		},
	}
	jsonData, _ := json.Marshal(finalResponse)
	return string(jsonData)
}

// sendSSEError sends an error message in SSE format
func (h *ResponseHandler) sendSSEError(w http.ResponseWriter, err error) {
	logger.Warn("sending SSE error response", zap.Error(err))

	// Default error code
	errorCode := types.ErrCodeInernalError
	message := types.ErrMsgInernalError
	errType := "server_error"

	// Check if the error is an APIError with a specific status code
	if apiErr, ok := err.(*types.APIError); ok {
		errorCode = apiErr.Code
		if apiErr.Type != "" {
			errType = apiErr.Type
		}
		if apiErr.Message != "" {
			message = apiErr.Message
		} else {
			message = fmt.Sprintf("status code: %d", apiErr.StatusCode)
		}
	}

	// Create error response in OpenAI format
	errorResponse := map[string]interface{}{
		"error": map[string]interface{}{
			"message": message,
			"type":    errType,
			"code":    errorCode,
		},
	}

	errorData, marshalErr := json.Marshal(errorResponse)
	if marshalErr != nil {
		logger.Error("failed to marshal error response",
			zap.Error(marshalErr),
		)
		fmt.Fprintf(w, "data: {\"error\":{\"message\":\"Internal server error\",\"type\":\"server_error\"}}\n\n")
	} else {
		fmt.Fprintf(w, "data: %s\n\n", string(errorData))
	}

	// Send [DONE] signal to close the stream
	fmt.Fprintf(w, "data: [DONE]\n\n")

	// Flush if possible
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
