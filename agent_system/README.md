# RMDS Agent System

基於 MCP (Model Context Protocol) 的多 Agent 協作工作流系統，專門為 RMDS (Runtime Memory Detection System) 專案設計。

## 核心組件

### 1. MCP Server (`mcp_server.py`)
- 提供安全的代碼讀寫操作
- 執行測試和靜態分析
- 權限控制和審計日誌

### 2. Workflow Orchestrator (`workflow_orchestrator.py`)
- 管理工作流生命週期
- 協調不同 Agent 的執行
- 整合 LLM 進行智能決策

### 3. LLM Client (`llm_client.py`)
- 統一的 LLM API 客戶端
- 支持 OpenAI 和 Anthropic
- 為不同任務配置適合的模型

## 工作流階段

1. **需求分析階段** - 使用 Claude 進行深度需求理解
2. **任務分解階段** - 使用 Claude 進行邏輯分析和規劃
3. **代碼開發階段** - 使用 GPT-4 進行高質量代碼生成
4. **代碼審查階段** - 使用 Claude 進行安全性和質量檢查
5. **靜態分析階段** - 結合工具和 Claude 進行代碼分析
6. **測試生成階段** - 使用 GPT-4 生成結構化測試
7. **質量評估階段** - 使用 Claude 進行綜合評估

## 快速開始

### 1. 環境設置

```bash
# 安裝依賴
pip install -r requirements.txt

# 設置環境變量
# 方法 1: 使用 .env 文件 (推薦)
cp env_example.txt .env
# 編輯 .env 文件，填入您的 API 金鑰

# 方法 2: 設置環境變量
export OPENAI_API_KEY="your-openai-api-key"
export ANTHROPIC_API_KEY="your-anthropic-api-key"
```

### 2. 配置 LLM

編輯 `llm_config.json` 來自定義每個任務使用的模型：

```json
{
  "requirement_analysis": {
    "provider": "anthropic",
    "model": "claude-3-sonnet-20240229",
    "max_tokens": 4000,
    "temperature": 0.1
  },
  "code_generation": {
    "provider": "openai",
    "model": "gpt-4-turbo-preview",
    "max_tokens": 6000,
    "temperature": 0.1
  }
}
```

### 3. 運行工作流

```bash
# 啟動工作流
python run_workflow.py run "添加新的記憶體檢測功能"

# 查看工作流狀態
python run_workflow.py list

# 查看詳細信息
python run_workflow.py show <workflow_id>
```

## LLM 模型配置

### 任務與模型對應

| 任務類型 | 推薦模型 | 提供商 | 原因 |
|---------|---------|--------|------|
| 需求分析 | Claude-3-Sonnet | Anthropic | 深度理解和分析能力強 |
| 任務分解 | Claude-3-Sonnet | Anthropic | 邏輯分析和規劃能力強 |
| 代碼生成 | GPT-4-Turbo | OpenAI | 代碼生成質量高 |
| 代碼審查 | Claude-3-Sonnet | Anthropic | 安全性和質量檢查 |
| 測試生成 | GPT-4-Turbo | OpenAI | 結構化代碼生成 |
| 質量評估 | Claude-3-Sonnet | Anthropic | 綜合分析能力強 |
| 靜態分析 | Claude-3-Sonnet | Anthropic | 代碼理解能力強 |

### 模型參數說明

- **max_tokens**: 最大輸出 token 數
- **temperature**: 創造性控制 (0.1 = 保守, 0.9 = 創造性)
- **top_p**: 核採樣參數
- **frequency_penalty**: 頻率懲罰
- **presence_penalty**: 存在懲罰

## 配置

### MCP Server 配置 (`policy.json`)

```json
{
  "write_allow": ["src/**/*.cpp", "include/**/*.hpp"],
  "read_allow": ["src/**/*", "include/**/*"],
  "deny": ["secrets/**", ".env*"],
  "max_patch_size": 1000,
  "max_file_size_mb": 10,
  "timeout_seconds": 300
}
```

### 權限控制

- **write_allow**: 允許寫入的文件路徑模式
- **read_allow**: 允許讀取的文件路徑模式
- **deny**: 禁止訪問的文件路徑模式
- **max_patch_size**: 最大補丁行數
- **max_file_size_mb**: 最大文件大小 (MB)
- **timeout_seconds**: 操作超時時間

## 監控和日誌

### 日誌文件

- `logs/workflow.log` - 工作流執行日誌
- `logs/mcp_server.log` - MCP 服務器日誌
- `logs/llm_client.log` - LLM 客戶端日誌

### 審計追蹤

每個操作都包含：
- 操作時間戳
- 執行 Agent
- 使用的模型和 token 消耗
- 操作結果和錯誤信息

## 安全考慮

1. **API 金鑰安全**: 使用環境變量存儲 API 金鑰
2. **權限隔離**: 通過 policy.json 控制文件訪問
3. **操作審計**: 所有操作都有詳細日誌
4. **乾運行**: 重要操作先進行乾運行檢查
5. **超時控制**: 防止長時間運行的操作

## 開發和擴展

### 添加新的 Agent

1. 在 `workflow_orchestrator.py` 中添加執行方法
2. 在 `llm_config.json` 中配置對應的模型
3. 在 `SYSTEM_PROMPTS` 中添加系統提示詞

### 自定義 LLM 提供商

1. 在 `llm_client.py` 中添加新的提供商
2. 實現對應的 API 調用方法
3. 更新配置和文檔

## 故障排除

### 常見問題

1. **API 金鑰錯誤**: 檢查環境變量設置
2. **權限拒絕**: 檢查 policy.json 配置
3. **模型不可用**: 檢查 API 配額和模型名稱
4. **超時錯誤**: 調整 timeout_seconds 參數

### 調試模式

```bash
# 啟用詳細日誌
export LOG_LEVEL=DEBUG
python run_workflow.py run "測試任務"
```

## 性能優化

1. **並行執行**: 支持多個任務並行執行
2. **緩存機制**: LLM 響應可以緩存
3. **批量處理**: 支持批量文件操作
4. **資源限制**: 控制並發操作數量

## 未來計劃

- [ ] 支持更多 LLM 提供商
- [ ] 添加 Web 界面
- [ ] 實現工作流模板
- [ ] 添加性能基準測試
- [ ] 支持自定義模型微調
