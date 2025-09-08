# RMDS Agent System - Templates Directory

這個目錄包含了 RMDS Agent 系統的所有模板和配置文件，用於標準化工作流程和確保一致性。

## 目錄結構

```
templates/
├── README.md                    # 本文件
├── requirement_spec.yaml        # 需求規格模板
├── task_plan_prompt.md          # 任務計劃生成提示詞
├── evaluation_report.yaml       # 評估報告模板
├── ci_pipeline.yaml            # CI/CD 流水線配置
└── event_schema.yaml           # 事件總線架構定義
```

## 模板說明

### 1. requirement_spec.yaml
**用途**: 標準化需求提交格式
**包含內容**:
- 需求背景與目標
- 功能和非功能需求
- 影響分析
- 技術規格
- 驗收標準
- 時間規劃
- 審核資訊

**使用方式**:
```bash
# 複製模板並填寫
cp templates/requirement_spec.yaml specs/SPEC-2025-001.yaml
# 編輯文件內容
```

### 2. task_plan_prompt.md
**用途**: Decision/Decomposition Agent 的提示詞模板
**包含內容**:
- 系統角色定義
- 任務拆分原則
- 任務類型分類
- 範例輸入與輸出
- 質量檢查清單

**使用方式**:
```python
# 在 Decision Agent 中使用
with open('templates/task_plan_prompt.md', 'r') as f:
    prompt_template = f.read()
    
# 填充實際需求內容
prompt = prompt_template.format(requirement_spec=spec_content)
```

### 3. evaluation_report.yaml
**用途**: Evaluation Agent 的評估報告模板
**包含內容**:
- 功能需求評估
- 非功能需求評估
- 測試結果評估
- 靜態分析評估
- 風險評估
- 部署準備評估

**使用方式**:
```python
# 在 Evaluation Agent 中生成報告
evaluation_data = {
    "evaluation_id": "EV-2025-001",
    "spec_id": "SPEC-2025-001",
    "decision": "accept",
    # ... 其他評估數據
}

# 使用模板生成報告
report = generate_evaluation_report(evaluation_data, template_path)
```

### 4. ci_pipeline.yaml
**用途**: GitHub Actions / GitLab CI 的靜態分析和測試流水線
**包含內容**:
- 靜態分析階段
- 編譯階段
- 單元測試階段
- 集成測試階段
- 性能測試階段
- 記憶體檢查階段
- 回歸測試階段
- 安全測試階段
- 評估階段
- 部署階段

**使用方式**:
```bash
# 複製到專案根目錄
cp templates/ci_pipeline.yaml .github/workflows/rmds-ci.yml

# 或在 GitLab 中
cp templates/ci_pipeline.yaml .gitlab-ci.yml
```

### 5. event_schema.yaml
**用途**: 定義 Orchestrator 事件總線的所有事件類型和結構
**包含內容**:
- 事件類型定義
- 事件路由規則
- 事件驗證規則
- 事件監控和指標
- 事件持久化配置

**使用方式**:
```python
# 在 EventBus 中載入架構
with open('templates/event_schema.yaml', 'r') as f:
    event_schema = yaml.safe_load(f)

# 驗證事件格式
validate_event(event, event_schema)
```

## 模板使用指南

### 1. 需求提交流程
1. 複製 `requirement_spec.yaml` 模板
2. 填寫需求相關資訊
3. 提交給 Requirement Normalizer Agent
4. 系統自動生成標準化規格

### 2. 任務規劃流程
1. Decision Agent 使用 `task_plan_prompt.md`
2. 分析需求規格
3. 生成詳細的任務計劃
4. 分配給相應的開發 Agent

### 3. 評估流程
1. Evaluation Agent 收集所有測試結果
2. 使用 `evaluation_report.yaml` 模板
3. 生成標準化評估報告
4. 做出接受/拒絕決策

### 4. CI/CD 流程
1. 將 `ci_pipeline.yaml` 配置到 CI/CD 系統
2. 自動觸發靜態分析和測試
3. 生成評估報告
4. 自動部署（如果通過）

### 5. 事件驅動流程
1. 所有 Agent 遵循 `event_schema.yaml` 定義
2. 標準化事件格式和路由
3. 確保系統可觀測性
4. 支援事件重放和調試

## 自定義和擴展

### 添加新的模板
1. 在 `templates/` 目錄下創建新文件
2. 遵循現有的命名規範
3. 更新本 README 文件
4. 在相應的 Agent 中集成

### 修改現有模板
1. 保持向後相容性
2. 更新版本號
3. 記錄變更日誌
4. 通知相關團隊

### 模板驗證
```bash
# 驗證 YAML 格式
python -c "import yaml; yaml.safe_load(open('templates/requirement_spec.yaml'))"

# 驗證 JSON Schema (如果適用)
python -m jsonschema -i data.json schema.json
```

## 最佳實踐

### 1. 模板版本控制
- 使用語義化版本號
- 記錄變更歷史
- 保持向後相容性

### 2. 模板驗證
- 自動化格式檢查
- 強制性欄位驗證
- 類型檢查

### 3. 模板文檔
- 詳細的使用說明
- 範例和最佳實踐
- 常見問題解答

### 4. 模板測試
- 單元測試覆蓋
- 集成測試驗證
- 端到端測試

## 故障排除

### 常見問題

1. **模板格式錯誤**
   ```bash
   # 檢查 YAML 語法
   python -c "import yaml; yaml.safe_load(open('template.yaml'))"
   ```

2. **模板載入失敗**
   ```python
   # 檢查文件路徑
   import os
   print(os.path.exists('templates/template.yaml'))
   ```

3. **事件架構不匹配**
   ```python
   # 驗證事件格式
   validate_event_structure(event, schema)
   ```

### 支援和聯繫

如有問題或建議，請：
1. 檢查本文件
2. 查看專案 Wiki
3. 提交 Issue
4. 聯繫開發團隊

## 更新日誌

### v1.0.0 (2025-01-08)
- 初始版本發布
- 包含所有核心模板
- 完整的文檔說明

### 計劃中的功能
- 模板生成器工具
- 自動化驗證腳本
- 模板管理儀表板
- 版本遷移工具
