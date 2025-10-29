package functions

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/zgsm-ai/chat-rag/internal/client"
	"github.com/zgsm-ai/chat-rag/internal/config"
	"github.com/zgsm-ai/chat-rag/internal/model"
	"github.com/zgsm-ai/chat-rag/internal/utils"
)

const (
	// CodeBaseSearchTool
	CodebaseSearchToolName   = "codebase_search"
	CodebaseSearchCapability = `- You can use codebase_search to perform semantic-aware searches across your codebase, 
returning conceptually relevant code snippets based on meaning rather than exact text matches. 
This is particularly powerful for discovering related functionality, exploring unfamiliar code architecture, 
or locating implementations when you only understand the purpose but not the specific syntax. 
For optimal efficiency, always try codebase_search first as it delivers more focused results with lower token consumption. 
Reserve other tools for cases where you need literal pattern matching or precise line-by-line analysis of file contents. 
This balanced approach ensures you get the right search method for each scenario - semantic discovery through codebase_search when possible, 
falling back to exhaustive text search via other tools only when necessary.
`
	CodebaseSearchToolDesc = `## codebase_search
Description: Find files most relevant to the search query.
This is a semantic search tool, so the query should ask for something semantically matching what is needed.
If it makes sense to only search in a particular directory, please specify it in the path parameter.
Unless there is a clear reason to use your own search query, please just reuse the user's exact query with their wording.
Their exact wording/phrasing can often be helpful for the semantic search query. 
Keeping the same exact question format can also be helpful.
IMPORTANT: Queries MUST be in English. Translate non-English queries before searching.
When you need to search for relevant codes, use this tool first.

Parameters:
- query: (required) The search query to find relevant code. You should reuse the user's exact query/most recent message with their wording unless there is a clear reason not to.
- path: (optional) The path to the directory to search in relative to the current working directory. This parameter should only be a directory path, file paths are not supported. Defaults to the current working directory.
Usage:
<codebase_search>
<query>Your natural language query here</query>
<path>Path to the directory to search in (optional)</path>
</codebase_search>

Example: Searching for functions related to user authentication
<codebase_search>
<query>User login and password hashing</query>
<path>/path/to/directory</path>
</codebase_search>
`

	// ReferenceSearchTool
	ReferenceSearchToolName   = "code_reference_search"
	ReferenceSearchCapability = `- You can use code_reference_search to retrieve comprehensive usage and call information for functions and methods across the entire codebase.
This tool is particularly useful when you need to locate all usages and trace reverse call chains (caller chains) of a function or method, or when analyzing code dependencies across different modules and files.
Compared to manually navigating directory structures and reading file contents, this tool provides a significantly faster and more accurate way to understand calling relationships between different functions and methods.
`
	ReferenceSearchToolDesc = `## code_reference_search
Description:
Retrieves the reverse call chain (caller chain) for a specified function or method within the codebase.
Given a target symbol, the tool traces all functions that directly or indirectly invoke it, offering a clear and context-rich view of its upstream dependencies.
You can specify a lineRange to precisely locate the target symbol, improving both the accuracy and efficiency of call chain generation.
This helps developers understand how a function or method is used, its relationships, and its dependency paths across the codebase.

**IMPORTANT: This only applies to seven languages: Java, Go, Python, C, CPP, JavaScript, and TypeScript. Other languages are not applicable.

Parameters:
- filePath: (required) The path of the file where the function or method is defined (relative to workspace directory)
- maxLayer: (required) Maximum call chain depth to search (default: 4, maximum: 10)
- symbolName: (required) The name of the function or method 
- lineRange: (optional) The line range of the function or method definition in format "start-end" (1-based)

Usage:

<code_reference_search>
  <filePath>path/to/file</filePath>
  <maxLayer>call chain depth (1-10)</maxLayer>
  <symbolName>symbol name</symbolName>
  <lineRange>start-end</lineRange>
</code_reference_search>

Examples
1. Exploring reverse call chain of the queryCallGraphBySymbol function 
<code_reference_search>
  <filePath>internal\service\indexer.go</filePath>
  <maxLayer>4</maxLayer>
  <symbolName>queryCallGraphBySymbol</symbolName>
</code_reference_search>

2. Exploring reverse call chain of the queryCallGraphByLineRange function with lineRange:
<code_reference_search>
  <filePath>internal\tokenizer\tokenizer.go</filePath>
  <maxLayer>5</maxLayer>
  <symbolName>queryCallGraphByLineRange</symbolName>
  <lineRange>20-75</lineRange>
</code_reference_search>
`

	// DefinitionSearchTool
	DefinitionToolName   = "code_definition_search"
	DefinitionCapability = `
You can use the code_definition_search tool to retrieve the complete definition and implementation of a specified symbol (function, class, method, interface, struct, or constant) by providing its symbol name. This can be particularly useful when you need to understand the detailed structure and implementation of a specific symbol within the codebase. You may need to call this tool multiple times to examine different symbols relevant to your task.
 - For example, when asked to make edits, review code, investigate bugs, analyze code, or refactor code, you might first use code_definition_search to obtain the target symbol's full definition and implementation, then analyze its structure and logic. If understanding how the symbol is used throughout the codebase would help with the analysis or planning, you can use code_reference_search to find where the symbol is referenced in other files or modules. This helps you understand the usage patterns, potential impact of changes, and provides fuller context for your analysis or recommendations.
`
	DefinitionToolDesc = `## code_definition_search
Description: 
Retrieve the complete definition and implementation of a symbol (function, class, method, interface, struct, or constant) by specifying its symbol name.  
This tool allows you to access the original definition and implementation of any symbol, whether it is used within the same file or across multiple files, providing comprehensive information to facilitate understanding of the code logic.  
Retrieved usages and invocations may include class or interface instantiations, function or method calls, constant references, and more.

Note: 
1. This tool only applies to seven languages: Java, Go, Python, C, CPP, JavaScript, and TypeScript. Other languages are not applicable.
2. This tool is more efficient and uses fewer tokens than regex matching or directly searching files to obtain symbol definitions.

Parameters:
- symbolNames: (required) One or more target symbol names to search for definitions. Separate each symbol name with a comma.

Usage:
<code_definition_search>
  <symbolNames>SymbolName1,SymbolName2</symbolNames>
</code_definition_search>


Examples:

1. Querying the definition of a single symbol:
<code_definition_search>
  <symbolNames>QueryCallGraphOptions</symbolNames>
</code_definition_search>

2. Querying multiple symbols (within the 8-symbol limit)
<code_definition_search>
  <symbolNames>countFilesAndSize,RelationNode,defaultCacheCapacity</symbolNames>
</code_definition_search>

IMPORTANT: You MUST follow this Efficient Symbol Query Strategy:
- You MUST query all related symbols together in a single operation (up to 8 symbols at once)
- You MUST obtain all necessary context before analyzing or modifying code
- You MUST obtain complete definition information for each referenced symbol
- You MUST prioritize the most critical symbols first when querying multiple symbols
- You MUST write each symbol name in plain form (e.g., types.QueryCallGraphOptions → QueryCallGraphOptions), omitting any package, namespace, or class prefixes.
- You MUST use subsequent queries for additional symbols if more than 8 need to be analyzed
`
	// DefinitionSearchTool
	KnowledgeSearchToolName   = "knowledge_base_search"
	KnowledgeSearchCapability = `- You can use knowledge_base_search to semantically search project-specific documentation including Markdown files and API documentation, 
extracting precise contextual knowledge for AI-assisted programming while filtering out generic information. 
This tool is essential when you need to generate code requiring project-specific implementations, custom tool classes/interfaces, or code template reuse where syntax details or parameter rules are unclear; 
troubleshoot project-specific errors such as custom exceptions, module call failures, or environment configuration issues; 
follow project-local coding conventions including naming prefixes, comment formats, and directory structures; 
or query project-developed APIs and third-party integrated APIs to confirm parameter constraints, return value formats, and calling permissions. 
Always include project context and module names in your queries for accurate matching against specialized terminology. 
Reserve this for project-specific knowledge while using codebase_search for actual code implementations.
`
	KnowledgeSearchToolDesc = `## knowledge_base_search
Description: Semantically search project-specific documentation including Markdown files and API documentation to extract precise project context and specifications.
This tool is designed to retrieve project-unique information such as development manuals, module documentation, interface comments, and proprietary API specifications.
It uses semantic matching to focus on project-specific content while filtering out generic programming information.

Parameters:
query: (required) Search query containing "project dimension + core requirement". Must include module names and document types (e.g., "Project X Order Module Custom Payment API Parameters")
topK: (required) Number of results to return. Set to 1 for simple queries (single parameter explanation), 2-3 for complex queries (troubleshooting processes, multi-API comparisons)
scoreThreshold: (required) Similarity score threshold ≥0.75 (higher threshold avoids matching generic content due to project-specific terminology/abbreviations)

Usage:
<knowledge_base_search>
<query>Your query with project context and module names</query>
<topK>Number of results (1-50, default 10)</topK>
<scoreThreshold>Minimum similarity score (≥0.75)</scoreThreshold>
</knowledge_base_search>

Examples:
Searching for pagination interface parameters in Project A user module:
<knowledge_base_search>
<query>Project A User Module Pagination API Parameters</query>
<topK>5</topK>
<scoreThreshold>0.75</scoreThreshold>
</knowledge_base_search>

Searching for Java class naming rules in Project B development standards:
<knowledge_base_search>
<query>Project B Development Specification Java Class Naming</query>
<topK>10</topK>
<scoreThreshold>0.75</scoreThreshold>
</knowledge_base_search>
`

	XmlToolsRules = `
====

TOOLS USE FOLLOW RULES

- Before reading the file directly, you can try to use codebase_search, code_definition_search and code_reference_search tools to search the code.
- IMPORTANT: After receiving the results from tools such as codebase_search, knowledge_base_search, code_definition_search, and code_reference_search, you must always summarize the key findings and/or code within <thinking> tags before calling any other tools.
- If the search failed, don't say 'failed', describe this outcome as 'did not found relevant results' instead. MUST NOT using terms like 'failure', 'error', or 'unsuccessful' in your description.
- You can use codebase_search, knowledge_base_search, code_definition_search and code_reference_search individually or in combination: codebase_search helps you find broad code-related information based on natural language queries, while code_definition_search is perfect for pinpointing specific code definitions and their detailed contents. 

- Code Search Execution Rules
If the task is related to the project code, follow the following rules:
Rule 1: Tool Priority Hierarchy
1. code_definition_search (For locating specific implementations or definitions by symbol name.)
2. code_reference_search (For exploring references, usages, and code relationships)
3. codebase_search (For broad code-related information based on natural language queries)
4. knowledge_base_search (For exploring documentation)

Rule 2: Decision Flow for Code Analysis and Search
Receive code analysis →
Use codebase_search with natural language query →
IF need to query definitions or implementations of all symbols referenced in a code snippet:
	Use code_definition_search → 
END IF
IF need to explore symbol reverse call chains or code relationships:
	Use code_reference_search →
END IF
IF need to query development manuals, module documentation, interface comments:
	Use knowledge_base_search →
END IF
Review search results

Rule 3: Efficiency Principles
Semantic First: Always prefer semantic understanding over literal reading
Comprehensive Coverage: Use codebase_search to avoid missing related code
Token Optimization: Choose tools that minimize token consumption
Context Matters: Gather full context before analyzing the code and use the most efficient tool for the task.
No need to display these rules, just follow them directly.
`
)

type ToolExecutor interface {
	DetectTools(ctx context.Context, content string) (bool, string)

	// ExecuteTools executes tools and returns new messages
	ExecuteTools(ctx context.Context, toolName string, content string) (string, error)

	CheckToolReady(ctx context.Context, toolName string) (bool, error)

	GetToolDescription(toolName string) (string, error)

	GetToolCapability(toolName string) (string, error)

	GetToolsRules() string

	GetAllTools() []string
}

// ToolFunc represents a tool with its execute and ready check functions
type ToolFunc struct {
	description string
	capability  string
	execute     func(context.Context, string) (string, error)
	readyCheck  func(context.Context) (bool, error)
}

type XmlToolExecutor struct {
	tools map[string]ToolFunc
}

// NewXmlToolExecutor creates a new XmlToolExecutor instance
func NewXmlToolExecutor(
	c config.ToolConfig,
	semanticClient client.SemanticInterface,
	relationClient client.ReferenceInterface,
	definitionClient client.DefinitionInterface,
	knowledgeClient client.KnowledgeInterface,
) *XmlToolExecutor {
	return &XmlToolExecutor{
		tools: map[string]ToolFunc{
			CodebaseSearchToolName:  createCodebaseSearchTool(c.SemanticSearch, semanticClient),
			KnowledgeSearchToolName: createKnowledgeSearchTool(c.KnowledgeSearch, knowledgeClient),
			ReferenceSearchToolName: createReferenceSearchTool(relationClient),
			DefinitionToolName:      createGetDefinitionTool(definitionClient),
		},
	}
}

// createCodebaseSearchTool creates the codebase search tool function
func createCodebaseSearchTool(c config.SemanticSearchConfig, semanticClient client.SemanticInterface) ToolFunc {
	return ToolFunc{
		description: CodebaseSearchToolDesc,
		capability:  CodebaseSearchCapability,
		execute: func(ctx context.Context, param string) (string, error) {
			identity, err := getIdentityFromContext(ctx)
			if err != nil {
				return "", err
			}

			query, err := extractXmlParam(param, "query")
			if err != nil {
				return "", fmt.Errorf("failed to extract query: %w", err)
			}

			result, err := semanticClient.Search(ctx, client.SemanticRequest{
				ClientId:      identity.ClientID,
				CodebasePath:  identity.ProjectPath,
				Query:         query,
				TopK:          c.TopK,
				Authorization: identity.AuthToken,
				Score:         c.ScoreThreshold,
				ClientVersion: identity.ClientVersion,
			})
			if err != nil {
				return "", fmt.Errorf("semantic search failed: %w", err)
			}

			return result, nil
		},
		readyCheck: func(ctx context.Context) (bool, error) {
			identity, err := getIdentityFromContext(ctx)
			if err != nil {
				return false, err
			}
			if identity.ClientID == "" {
				return false, fmt.Errorf("get none clientId")
			}

			return semanticClient.CheckReady(context.Background(), client.ReadyRequest{
				ClientId:      identity.ClientID,
				CodebasePath:  identity.ProjectPath,
				Authorization: identity.AuthToken,
				ClientVersion: identity.ClientVersion,
			})
		},
	}
}

// createGetDefinitionTool creates the code definition search tool function
func createGetDefinitionTool(definitionClient client.DefinitionInterface) ToolFunc {
	return ToolFunc{
		description: DefinitionToolDesc,
		capability:  DefinitionCapability,
		execute: func(ctx context.Context, param string) (string, error) {
			identity, err := getIdentityFromContext(ctx)
			if err != nil {
				return "", err
			}

			req, err := buildDefinitionRequest(identity, param)
			if err != nil {
				return "", fmt.Errorf("failed to build request: %w", err)
			}

			result, err := definitionClient.Search(ctx, req)
			if err != nil {
				return "", fmt.Errorf("code definition search failed: %w", err)
			}

			return result, nil
		},
		readyCheck: func(ctx context.Context) (bool, error) {
			identity, err := getIdentityFromContext(ctx)
			if err != nil {
				return false, err
			}
			if identity.ClientID == "" {
				return false, fmt.Errorf("get none clientId")
			}

			return definitionClient.CheckReady(context.Background(), client.ReadyRequest{
				ClientId:      identity.ClientID,
				CodebasePath:  identity.ProjectPath,
				Authorization: identity.AuthToken,
				ClientVersion: identity.ClientVersion,
			})
		},
	}
}

// createReferenceSearchTool creates the relation search tool function
func createReferenceSearchTool(referenceClient client.ReferenceInterface) ToolFunc {
	return ToolFunc{
		description: ReferenceSearchToolDesc,
		capability:  ReferenceSearchCapability,
		execute: func(ctx context.Context, param string) (string, error) {
			identity, err := getIdentityFromContext(ctx)
			if err != nil {
				return "", err
			}

			req, err := buildRerenceRequest(identity, param)
			if err != nil {
				return "", fmt.Errorf("failed to build request: %w", err)
			}

			result, err := referenceClient.Search(ctx, req)
			if err != nil {
				return "", fmt.Errorf("relation search failed: %w", err)
			}

			return utils.MarshalJSONWithoutEscapeHTML(result)
		},
		readyCheck: func(ctx context.Context) (bool, error) {
			identity, err := getIdentityFromContext(ctx)
			if err != nil {
				return false, err
			}
			if identity.ClientID == "" {
				return false, fmt.Errorf("get none clientId")
			}

			return referenceClient.CheckReady(context.Background(), client.ReadyRequest{
				ClientId:      identity.ClientID,
				CodebasePath:  identity.ProjectPath,
				Authorization: identity.AuthToken,
				ClientVersion: identity.ClientVersion,
			})
		},
	}
}

// createKnowledgeSearchTool creates the knowledge base search tool function
func createKnowledgeSearchTool(c config.KnowledgeSearchConfig, knowledgeClient client.KnowledgeInterface) ToolFunc {
	return ToolFunc{
		description: KnowledgeSearchToolDesc,
		capability:  KnowledgeSearchCapability,
		execute: func(ctx context.Context, param string) (string, error) {
			identity, err := getIdentityFromContext(ctx)
			if err != nil {
				return "", err
			}

			query, err := extractXmlParam(param, "query")
			if err != nil {
				return "", fmt.Errorf("failed to extract query: %w", err)
			}

			result, err := knowledgeClient.Search(ctx, client.KnowledgeRequest{
				ClientId:      identity.ClientID,
				CodebasePath:  identity.ProjectPath,
				Query:         query,
				TopK:          c.TopK,
				Score:         c.ScoreThreshold,
				Authorization: identity.AuthToken,
				ClientVersion: identity.ClientVersion,
			})
			if err != nil {
				return "", fmt.Errorf("knowledge base search failed: %w", err)
			}

			return result, nil
		},
		readyCheck: func(ctx context.Context) (bool, error) {
			identity, err := getIdentityFromContext(ctx)
			if err != nil {
				return false, err
			}
			if identity.ClientID == "" {
				return false, fmt.Errorf("get none clientId")
			}

			return knowledgeClient.CheckReady(context.Background(), client.ReadyRequest{
				ClientId:      identity.ClientID,
				CodebasePath:  identity.ProjectPath,
				Authorization: identity.AuthToken,
				ClientVersion: identity.ClientVersion,
			})
		},
	}
}

// buildDefinitionRequest constructs a DefinitionRequest from XML parameters
func buildDefinitionRequest(identity *model.Identity, param string) (client.DefinitionRequest, error) {
	req := client.DefinitionRequest{
		ClientId:      identity.ClientID,
		CodebasePath:  identity.ProjectPath,
		Authorization: identity.AuthToken,
		ClientVersion: identity.ClientVersion,
	}

	// Check if using symbolName query mode
	if symbolName, err := extractXmlParam(param, "symbolName"); err == nil {
		req.SymbolName = symbolName
		return req, nil
	}

	// Use file path and line number query mode
	var err error
	if req.FilePath, err = extractXmlParam(param, "filePath"); err != nil {
		return req, fmt.Errorf("filePath: %w", err)
	}

	codebasePath := req.CodebasePath
	// Check the operating system type and convert the file path separator if it is a Windows system
	if strings.Contains(strings.ToLower(identity.ClientOS), "windows") {
		req.FilePath = strings.ReplaceAll(req.FilePath, "/", "\\")
		codebasePath = strings.ReplaceAll(codebasePath, "/", "\\")
	}

	if !strings.Contains(req.FilePath, codebasePath) {
		return req, fmt.Errorf("filePath must be full absolute path, please try again")
	}

	// Optional parameters
	if startLine, err := extractXmlIntParam(param, "startLine"); err == nil {
		req.StartLine = &startLine
	}

	if endLine, err := extractXmlIntParam(param, "endLine"); err == nil {
		req.EndLine = &endLine
	}

	return req, nil
}

// buildRerenceRequest constructs a RelationRequest from XML parameters
func buildRerenceRequest(identity *model.Identity, param string) (client.ReferenceRequest, error) {
	req := client.ReferenceRequest{
		ClientId:      identity.ClientID,
		CodebasePath:  identity.ProjectPath,
		Authorization: identity.AuthToken,
		ClientVersion: identity.ClientVersion,
	}

	// Process required parameters: filePath and symbolName (at least one is needed)
	symbolName, _ := extractXmlParam(param, "symbolName")
	if symbolName != "" {
		req.SymbolName = symbolName
	}

	// filePath is required
	if err := processFilePath(&req, identity, param); err != nil {
		return req, err
	}

	// Process optional parameters
	processOptionalParams(&req, param)

	return req, nil
}

// processFilePath handles file path related logic
func processFilePath(req *client.ReferenceRequest, identity *model.Identity, param string) error {
	var err error
	if req.FilePath, err = extractXmlParam(param, "filePath"); err != nil {
		return fmt.Errorf("filePath: %w", err)
	}

	// Process file path separators
	codebasePath := req.CodebasePath
	if strings.Contains(strings.ToLower(identity.ClientOS), "windows") {
		req.FilePath = strings.ReplaceAll(req.FilePath, "/", "\\")
		codebasePath = strings.ReplaceAll(codebasePath, "/", "\\")
	}

	// Validate file path
	if !strings.Contains(req.FilePath, codebasePath) {
		return fmt.Errorf("filePath must be full absolute path, please try again")
	}

	return nil
}

// processOptionalParams handles optional parameters
func processOptionalParams(req *client.ReferenceRequest, param string) {
	// Process startLine and endLine
	if startLine, err := extractXmlIntParam(param, "startLine"); err == nil {
		req.StartLine = &startLine
	}

	if endLine, err := extractXmlIntParam(param, "endLine"); err == nil {
		req.EndLine = &endLine
	}

	// Process maxLayer, default is 10
	if maxLayer, err := extractXmlIntParam(param, "maxLayer"); err == nil {
		if maxLayer > 0 && maxLayer <= 10 {
			req.MaxLayer = &maxLayer
		}
	} else {
		defaultMaxLayer := 10
		req.MaxLayer = &defaultMaxLayer
	}
}

// Helper functions

func getIdentityFromContext(ctx context.Context) (*model.Identity, error) {
	identity, exists := model.GetIdentityFromContext(ctx)
	if !exists {
		return nil, fmt.Errorf("identity not found in context")
	}
	return identity, nil
}

func extractXmlParam(content, paramName string) (string, error) {
	startTag := "<" + paramName + ">"
	endTag := "</" + paramName + ">"

	start := strings.Index(content, startTag)
	if start == -1 {
		return "", fmt.Errorf("start tag not found")
	}

	end := strings.Index(content, endTag)
	if end == -1 {
		return "", fmt.Errorf("end tag not found")
	}

	paramValue := content[start+len(startTag) : end]

	// Check and replace double backslashes with single backslashes to conform to Windows path format
	paramValue = strings.ReplaceAll(paramValue, "\\\\", "\\")

	return paramValue, nil
}

func extractXmlIntParam(content, paramName string) (int, error) {
	param, err := extractXmlParam(content, paramName)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(param)
}

// Implement remaining ToolExecutor interface methods...

// DetectTools only detects if tool calls are included and extracts tool information
// Returns: whether tool is detected, tool name
func (x *XmlToolExecutor) DetectTools(ctx context.Context, content string) (bool, string) {
	for toolName := range x.tools {
		if strings.Contains(content, "<"+toolName+">") {
			return true, toolName
		}
	}
	return false, ""
}

// ExecuteTools executes the specified tool and constructs new messages
func (x *XmlToolExecutor) ExecuteTools(ctx context.Context, toolName string, content string) (string, error) {
	// Get tool function
	toolFunc, exists := x.tools[toolName]
	if !exists {
		return "", fmt.Errorf("tool %s not found", toolName)
	}

	param, err := extractXmlParam(content, toolName)
	if err != nil {
		return "", fmt.Errorf("failed to extract tool parameters: %w", err)
	}

	return toolFunc.execute(ctx, param)
}

// CheckApiReady checks if the tool is ready to use
func (x *XmlToolExecutor) CheckToolReady(ctx context.Context, toolName string) (bool, error) {
	toolFunc, exists := x.tools[toolName]
	if !exists {
		return false, fmt.Errorf("tool %s not found", toolName)
	}

	// tool does not require ready check
	if toolFunc.readyCheck == nil {
		return true, nil
	}

	return toolFunc.readyCheck(ctx)
}

// GetToolDescription returns the description of the specified tool
func (x *XmlToolExecutor) GetToolDescription(toolName string) (string, error) {
	toolFunc, exists := x.tools[toolName]
	if !exists {
		return "", fmt.Errorf("tool %s not found", toolName)
	}

	return toolFunc.description, nil
}

// GetToolCapability returns the capability of the specified tool
func (x *XmlToolExecutor) GetToolCapability(toolName string) (string, error) {
	toolFunc, exists := x.tools[toolName]
	if !exists {
		return "", fmt.Errorf("tool %s not found", toolName)
	}

	return toolFunc.capability, nil
}

// GetAllTools returns the names of all registered tools
func (x *XmlToolExecutor) GetAllTools() []string {
	tools := make([]string, 0, len(x.tools))
	for name := range x.tools {
		tools = append(tools, name)
	}
	return tools
}

// GetToolsRules returns the tools use rules
func (x *XmlToolExecutor) GetToolsRules() string {
	return XmlToolsRules
}
