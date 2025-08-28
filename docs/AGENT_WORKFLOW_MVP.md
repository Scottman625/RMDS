# RMDS Agent 工作流 MVP 設計

## 概述

本設計為 RMDS（實時記憶體攻擊檢測引擎）建立一個最小可行產品 (MVP) 的多 Agent 協作工作流，專注於自動化威脅檢測、特徵工程和模型優化。

## 一、MVP 核心設計原則

### 1.1 分層架構
- **Layer 0**: 硬體層 - 記憶體事件收集
- **Layer 1**: 資料層 - 特徵提取與標準化  
- **Layer 2**: 分析層 - 威脅檢測與模型推理
- **Layer 3**: 協調層 - 工作流編排與決策
- **Layer 4**: 營運層 - 監控與回饋

### 1.2 核心原則
- **事件驅動**: 基於 Kafka/RabbitMQ 的異步事件處理
- **生成+驗證配對**: 每個生成 Agent 配對驗證 Agent
- **可觀測性**: 所有事件帶 metadata 和 trace ID
- **安全優先**: 敏感資料匿名化處理
- **漸進式擴展**: 從 6 個核心 Agent 開始

## 二、MVP Agent 矩陣

### 2.1 核心 Agent 定義

#### A. Orchestrator Agent (調度中樞)
```yaml
name: orchestrator
role: 工作流編排與任務調度
inputs:
  - threat_update
  - detection_alert
  - model_drift
  - feature_request
outputs:
  - task_queue
  - deployment_decision
  - rollback_trigger
kpi:
  - 任務完成時間 (MTTC)
  - 失敗重試率
  - 決策準確率
```

#### B. Threat Intel Agent (威脅情報)
```yaml
name: threat_intel_agent
role: 威脅情報收集與分析
inputs:
  - cve_feed
  - security_reports
  - attack_patterns
outputs:
  - threat_summary
  - attack_chain_mapping
  - confidence_score
kpi:
  - 情報新鮮度 (發布→分析時間)
  - 摘要準確率
  - 覆蓋率
```

#### C. Feature Designer Agent (特徵設計)
```yaml
name: feature_designer
role: 記憶體特徵工程
inputs:
  - threat_summary
  - baseline_stats
  - performance_constraints
outputs:
  - feature_spec
  - resource_estimate
  - validation_criteria
kpi:
  - 特徵有效性
  - 資源使用率
  - 實現轉化率
```

#### D. Detection Engine Agent (檢測引擎)
```yaml
name: detection_engine
role: 實時攻擊檢測
inputs:
  - memory_events
  - feature_specs
  - detection_rules
outputs:
  - attack_alerts
  - confidence_scores
  - performance_metrics
kpi:
  - 檢測延遲
  - 真陽性率 (TPR)
  - 假陽性率 (FPR)
```

#### E. Model Trainer Agent (模型訓練)
```yaml
name: model_trainer
role: 機器學習模型訓練
inputs:
  - labeled_data
  - feature_sets
  - performance_targets
outputs:
  - trained_model
  - performance_metrics
  - drift_indicators
kpi:
  - 模型準確率
  - 訓練時間
  - 漂移檢測準確率
```

#### F. Attack Simulator Agent (攻擊模擬)
```yaml
name: attack_simulator
role: 攻擊場景回放與驗證
inputs:
  - attack_scenarios
  - target_environment
  - validation_rules
outputs:
  - simulation_results
  - detection_performance
  - false_positive_analysis
kpi:
  - 場景覆蓋率
  - 檢測準確率
  - 模擬真實性
```

## 三、事件驅動工作流

### 3.1 核心事件類型

```json
{
  "event_type": "threat_update",
  "id": "evt-2024-01-15-001",
  "producer": "threat_intel_agent",
  "timestamp": "2024-01-15T10:30:00Z",
  "trace_id": "trace-abc123",
  "payload": {
    "threat_name": "PipeMagic_variant",
    "attack_chain": ["T1055", "T1027", "T1071"],
    "memory_patterns": ["executable_churn", "low_freq_c2"],
    "confidence": 0.85,
    "source": "CVE-2024-1234"
  }
}
```

```json
{
  "event_type": "feature_spec_ready",
  "id": "evt-2024-01-15-002", 
  "producer": "feature_designer",
  "timestamp": "2024-01-15T10:35:00Z",
  "trace_id": "trace-abc123",
  "payload": {
    "feature_name": "executable_page_churn_ratio",
    "definition": "count(new_exec_pages - released_exec_pages) / total_stable_exec_pages",
    "window_size": "30s",
    "resource_estimate": {
      "memory_kb": 64,
      "cpu_cycles": 1000,
      "latency_ms": 5
    },
    "validation_criteria": {
      "max_fpr": 0.01,
      "min_tpr": 0.95
    }
  }
}
```

### 3.2 工作流序列

#### 新威脅響應流程
1. **Threat Intel Agent** 接收 CVE/威脅情報
2. 發出 `threat_update` 事件
3. **Orchestrator** 接收並分析威脅
4. **Feature Designer** 設計對應特徵
5. 發出 `feature_spec_ready` 事件
6. **Detection Engine** 整合新特徵
7. **Attack Simulator** 驗證檢測效果
8. **Model Trainer** 重新訓練模型
9. **Orchestrator** 決策部署

#### 模型漂移處理流程
1. **Detection Engine** 檢測性能下降
2. 發出 `model_drift` 事件
3. **Orchestrator** 觸發重新訓練
4. **Model Trainer** 分析漂移原因
5. **Feature Designer** 調整特徵
6. **Attack Simulator** 驗證新模型
7. **Orchestrator** 決策是否部署

## 四、技術實作架構

### 4.1 事件總線設計

```python
# events/event_bus.py
import asyncio
import json
from typing import Dict, Any, Callable
from dataclasses import dataclass
from datetime import datetime
import uuid

@dataclass
class Event:
    event_type: str
    id: str
    producer: str
    timestamp: str
    trace_id: str
    payload: Dict[str, Any]

class EventBus:
    def __init__(self):
        self.subscribers: Dict[str, list[Callable]] = {}
        self.event_history: list[Event] = []
    
    async def publish(self, event: Event):
        """發布事件到所有訂閱者"""
        self.event_history.append(event)
        
        if event.event_type in self.subscribers:
            for callback in self.subscribers[event.event_type]:
                await callback(event)
    
    def subscribe(self, event_type: str, callback: Callable):
        """訂閱特定事件類型"""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)
    
    def create_event(self, event_type: str, producer: str, payload: Dict[str, Any], trace_id: str = None) -> Event:
        """創建標準化事件"""
        return Event(
            event_type=event_type,
            id=f"evt-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}-{str(uuid.uuid4())[:8]}",
            producer=producer,
            timestamp=datetime.now().isoformat(),
            trace_id=trace_id or str(uuid.uuid4()),
            payload=payload
        )
```

### 4.2 Agent 基礎類別

```python
# agents/base_agent.py
from abc import ABC, abstractmethod
from typing import Dict, Any
from events.event_bus import EventBus, Event

class BaseAgent(ABC):
    def __init__(self, name: str, event_bus: EventBus):
        self.name = name
        self.event_bus = event_bus
        self.setup_subscriptions()
    
    @abstractmethod
    def setup_subscriptions(self):
        """設置事件訂閱"""
        pass
    
    @abstractmethod
    async def process_event(self, event: Event):
        """處理接收的事件"""
        pass
    
    async def publish_event(self, event_type: str, payload: Dict[str, Any], trace_id: str = None):
        """發布事件"""
        event = self.event_bus.create_event(event_type, self.name, payload, trace_id)
        await self.event_bus.publish(event)
    
    def log_activity(self, message: str, level: str = "INFO"):
        """記錄活動日誌"""
        print(f"[{level}] {self.name}: {message}")
```

### 4.3 Orchestrator Agent 實作

```python
# agents/orchestrator.py
import asyncio
from typing import Dict, List
from agents.base_agent import BaseAgent
from events.event_bus import Event

class OrchestratorAgent(BaseAgent):
    def __init__(self, event_bus):
        super().__init__("orchestrator", event_bus)
        self.task_queue: List[Dict] = []
        self.active_tasks: Dict[str, Dict] = {}
        self.deployment_history: List[Dict] = []
    
    def setup_subscriptions(self):
        """訂閱關鍵事件"""
        self.event_bus.subscribe("threat_update", self.handle_threat_update)
        self.event_bus.subscribe("model_drift", self.handle_model_drift)
        self.event_bus.subscribe("feature_spec_ready", self.handle_feature_ready)
        self.event_bus.subscribe("detection_alert", self.handle_detection_alert)
    
    async def handle_threat_update(self, event: Event):
        """處理威脅更新事件"""
        self.log_activity(f"處理新威脅: {event.payload.get('threat_name')}")
        
        # 創建特徵設計任務
        task = {
            "id": f"task-{event.id}",
            "type": "feature_design",
            "threat_data": event.payload,
            "priority": "high",
            "status": "pending"
        }
        
        self.task_queue.append(task)
        await self.schedule_tasks()
    
    async def handle_model_drift(self, event: Event):
        """處理模型漂移事件"""
        self.log_activity("檢測到模型漂移，觸發重新訓練")
        
        # 觸發模型重新訓練
        await self.publish_event("retrain_request", {
            "reason": "model_drift",
            "drift_metrics": event.payload.get("drift_metrics"),
            "urgency": "medium"
        }, event.trace_id)
    
    async def handle_feature_ready(self, event: Event):
        """處理特徵規格就緒事件"""
        self.log_activity(f"新特徵就緒: {event.payload.get('feature_name')}")
        
        # 觸發檢測引擎更新
        await self.publish_event("feature_update", {
            "feature_spec": event.payload,
            "deployment_type": "canary"
        }, event.trace_id)
    
    async def handle_detection_alert(self, event: Event):
        """處理檢測警報事件"""
        self.log_activity(f"檢測警報: {event.payload.get('attack_type')}")
        
        # 記錄警報並觸發響應
        await self.publish_event("alert_response", {
            "alert_id": event.id,
            "response_actions": ["isolate", "analyze", "report"]
        }, event.trace_id)
    
    async def schedule_tasks(self):
        """調度待處理任務"""
        for task in self.task_queue[:]:
            if task["status"] == "pending":
                await self.execute_task(task)
    
    async def execute_task(self, task: Dict):
        """執行任務"""
        task["status"] = "running"
        self.active_tasks[task["id"]] = task
        
        try:
            if task["type"] == "feature_design":
                await self.publish_event("design_feature", {
                    "threat_data": task["threat_data"],
                    "task_id": task["id"]
                })
            
            task["status"] = "completed"
        except Exception as e:
            task["status"] = "failed"
            task["error"] = str(e)
            self.log_activity(f"任務失敗: {e}", "ERROR")
        
        self.task_queue.remove(task)
        if task["id"] in self.active_tasks:
            del self.active_tasks[task["id"]]
```

### 4.4 Threat Intel Agent 實作

```python
# agents/threat_intel.py
import asyncio
import aiohttp
import json
from typing import Dict, List
from agents.base_agent import BaseAgent
from events.event_bus import Event

class ThreatIntelAgent(BaseAgent):
    def __init__(self, event_bus):
        super().__init__("threat_intel_agent", event_bus)
        self.cve_sources = [
            "https://cve.mitre.org/data/downloads/allitems.csv",
            "https://nvd.nist.gov/vuln/data-feeds"
        ]
        self.threat_patterns = {
            "memory_attacks": ["ROP", "JOP", "buffer_overflow", "heap_corruption"],
            "injection_attacks": ["shellcode", "dll_injection", "process_hollowing"],
            "evasion_techniques": ["antidebug", "antivm", "code_obfuscation"]
        }
    
    def setup_subscriptions(self):
        """設置事件訂閱"""
        self.event_bus.subscribe("cve_feed_update", self.handle_cve_update)
        self.event_bus.subscribe("security_report", self.handle_security_report)
    
    async def handle_cve_update(self, event: Event):
        """處理 CVE 更新"""
        cve_data = event.payload
        await self.analyze_cve(cve_data)
    
    async def handle_security_report(self, event: Event):
        """處理安全報告"""
        report_data = event.payload
        await self.analyze_report(report_data)
    
    async def analyze_cve(self, cve_data: Dict):
        """分析 CVE 資料"""
        # 提取記憶體相關攻擊模式
        memory_related = self.extract_memory_patterns(cve_data.get("description", ""))
        
        if memory_related:
            threat_summary = {
                "threat_name": cve_data.get("cve_id"),
                "attack_chain": self.map_attack_chain(cve_data),
                "memory_patterns": memory_related,
                "confidence": self.calculate_confidence(cve_data),
                "source": "CVE",
                "severity": cve_data.get("severity", "medium")
            }
            
            await self.publish_event("threat_update", threat_summary)
    
    def extract_memory_patterns(self, description: str) -> List[str]:
        """從描述中提取記憶體攻擊模式"""
        patterns = []
        description_lower = description.lower()
        
        for category, pattern_list in self.threat_patterns.items():
            for pattern in pattern_list:
                if pattern.lower() in description_lower:
                    patterns.append(pattern)
        
        return patterns
    
    def map_attack_chain(self, cve_data: Dict) -> List[str]:
        """映射 MITRE ATT&CK 戰術"""
        # 簡化的戰術映射
        tactics = []
        description = cve_data.get("description", "").lower()
        
        if "injection" in description:
            tactics.append("T1055")  # Process Injection
        if "execution" in description:
            tactics.append("T1059")  # Command and Scripting Interpreter
        if "defense" in description:
            tactics.append("T1562")  # Impair Defenses
        
        return tactics
    
    def calculate_confidence(self, cve_data: Dict) -> float:
        """計算威脅情報信心分數"""
        confidence = 0.5  # 基礎分數
        
        # 根據描述詳細度調整
        if len(cve_data.get("description", "")) > 200:
            confidence += 0.2
        
        # 根據嚴重程度調整
        severity = cve_data.get("severity", "medium")
        if severity == "high":
            confidence += 0.2
        elif severity == "critical":
            confidence += 0.3
        
        return min(confidence, 1.0)
    
    async def start_monitoring(self):
        """開始監控威脅情報源"""
        self.log_activity("開始監控威脅情報源")
        
        # 模擬定期檢查 CVE 源
        while True:
            try:
                # 這裡可以實作實際的 CVE 源檢查
                await asyncio.sleep(3600)  # 每小時檢查一次
                
                # 模擬發現新威脅
                if self.should_simulate_threat():
                    await self.simulate_threat_discovery()
                    
            except Exception as e:
                self.log_activity(f"監控錯誤: {e}", "ERROR")
                await asyncio.sleep(60)
    
    def should_simulate_threat(self) -> bool:
        """決定是否模擬威脅發現"""
        import random
        return random.random() < 0.1  # 10% 機率
    
    async def simulate_threat_discovery(self):
        """模擬威脅發現"""
        simulated_threat = {
            "threat_name": "Simulated_Memory_Attack",
            "attack_chain": ["T1055", "T1027"],
            "memory_patterns": ["ROP", "shellcode_injection"],
            "confidence": 0.8,
            "source": "simulation",
            "severity": "high"
        }
        
        await self.publish_event("threat_update", simulated_threat)
        self.log_activity("模擬威脅發現完成")
```

## 五、部署與配置

### 5.1 主程序實作

```python
# main.py
import asyncio
import signal
import sys
from events.event_bus import EventBus
from agents.orchestrator import OrchestratorAgent
from agents.threat_intel import ThreatIntelAgent
from agents.feature_designer import FeatureDesignerAgent
from agents.detection_engine import DetectionEngineAgent
from agents.model_trainer import ModelTrainerAgent
from agents.attack_simulator import AttackSimulatorAgent

class RMDSAgentSystem:
    def __init__(self):
        self.event_bus = EventBus()
        self.agents = {}
        self.running = False
    
    def setup_agents(self):
        """設置所有 Agent"""
        self.agents["orchestrator"] = OrchestratorAgent(self.event_bus)
        self.agents["threat_intel"] = ThreatIntelAgent(self.event_bus)
        self.agents["feature_designer"] = FeatureDesignerAgent(self.event_bus)
        self.agents["detection_engine"] = DetectionEngineAgent(self.event_bus)
        self.agents["model_trainer"] = ModelTrainerAgent(self.event_bus)
        self.agents["attack_simulator"] = AttackSimulatorAgent(self.event_bus)
        
        print(f"已初始化 {len(self.agents)} 個 Agent")
    
    async def start_system(self):
        """啟動系統"""
        self.running = True
        self.setup_agents()
        
        # 啟動所有 Agent 的監控任務
        tasks = []
        for name, agent in self.agents.items():
            if hasattr(agent, 'start_monitoring'):
                task = asyncio.create_task(agent.start_monitoring())
                tasks.append(task)
        
        print("RMDS Agent 系統已啟動")
        
        # 等待系統運行
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            print("收到中斷信號，正在關閉...")
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """關閉系統"""
        self.running = False
        print("正在關閉 RMDS Agent 系統...")
        
        # 這裡可以添加清理邏輯
        await asyncio.sleep(1)
        print("系統已關閉")

def signal_handler(signum, frame):
    """信號處理器"""
    print(f"收到信號 {signum}，正在關閉...")
    sys.exit(0)

async def main():
    """主函數"""
    # 設置信號處理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 創建並啟動系統
    system = RMDSAgentSystem()
    await system.start_system()

if __name__ == "__main__":
    asyncio.run(main())
```

### 5.2 配置文件

```yaml
# config/agent_config.yaml
agents:
  orchestrator:
    enabled: true
    log_level: INFO
    max_concurrent_tasks: 10
    
  threat_intel:
    enabled: true
    log_level: INFO
    cve_check_interval: 3600  # 秒
    sources:
      - "https://cve.mitre.org/data/downloads/allitems.csv"
      - "https://nvd.nist.gov/vuln/data-feeds"
    
  feature_designer:
    enabled: true
    log_level: INFO
    max_features_per_threat: 5
    resource_limits:
      max_memory_kb: 1024
      max_cpu_cycles: 10000
      max_latency_ms: 10
    
  detection_engine:
    enabled: true
    log_level: INFO
    scan_interval_ms: 100
    max_processes: 200
    detection_threshold: 0.7
    
  model_trainer:
    enabled: true
    log_level: INFO
    training_interval: 86400  # 24小時
    model_registry_path: "./models"
    
  attack_simulator:
    enabled: true
    log_level: INFO
    simulation_interval: 3600  # 每小時
    attack_scenarios:
      - "rop_attack"
      - "buffer_overflow"
      - "shellcode_injection"

events:
  bus_type: "memory"  # 或 "kafka", "rabbitmq"
  retention_days: 30
  max_queue_size: 10000

logging:
  level: INFO
  file: "./logs/agent_system.log"
  max_size_mb: 100
  backup_count: 5

security:
  enable_encryption: false
  enable_authentication: false
  max_event_size_kb: 1024
```

## 六、監控與 KPI

### 6.1 KPI 儀表板

```python
# monitoring/kpi_dashboard.py
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List
import json

class KPIDashboard:
    def __init__(self):
        self.metrics = {
            "threat_detection": {
                "total_threats": 0,
                "detection_rate": 0.0,
                "avg_response_time": 0.0
            },
            "feature_engineering": {
                "features_created": 0,
                "avg_creation_time": 0.0,
                "success_rate": 0.0
            },
            "model_performance": {
                "accuracy": 0.0,
                "false_positive_rate": 0.0,
                "drift_detected": 0
            },
            "system_health": {
                "agent_uptime": {},
                "event_throughput": 0,
                "error_rate": 0.0
            }
        }
    
    def update_threat_metrics(self, threats_detected: int, response_time: float):
        """更新威脅檢測指標"""
        self.metrics["threat_detection"]["total_threats"] += threats_detected
        # 更新平均響應時間
        current_avg = self.metrics["threat_detection"]["avg_response_time"]
        total_threats = self.metrics["threat_detection"]["total_threats"]
        self.metrics["threat_detection"]["avg_response_time"] = (
            (current_avg * (total_threats - threats_detected) + response_time * threats_detected) / total_threats
        )
    
    def update_feature_metrics(self, features_created: int, creation_time: float, success: bool):
        """更新特徵工程指標"""
        self.metrics["feature_engineering"]["features_created"] += features_created
        # 更新平均創建時間
        current_avg = self.metrics["feature_engineering"]["avg_creation_time"]
        total_features = self.metrics["feature_engineering"]["features_created"]
        self.metrics["feature_engineering"]["avg_creation_time"] = (
            (current_avg * (total_features - features_created) + creation_time * features_created) / total_features
        )
        
        # 更新成功率
        if success:
            self.metrics["feature_engineering"]["success_rate"] += 1
    
    def get_dashboard_data(self) -> Dict:
        """獲取儀表板資料"""
        return {
            "timestamp": datetime.now().isoformat(),
            "metrics": self.metrics,
            "summary": self.generate_summary()
        }
    
    def generate_summary(self) -> Dict:
        """生成摘要報告"""
        return {
            "total_events_processed": sum(self.metrics["system_health"].values()),
            "system_status": "healthy" if self.metrics["system_health"]["error_rate"] < 0.05 else "warning",
            "last_updated": datetime.now().isoformat()
        }
    
    async def start_monitoring(self):
        """開始監控"""
        while True:
            # 每分鐘更新一次指標
            await asyncio.sleep(60)
            
            # 這裡可以添加實際的指標收集邏輯
            dashboard_data = self.get_dashboard_data()
            
            # 輸出到日誌或發送到監控系統
            print(f"KPI 更新: {json.dumps(dashboard_data, indent=2)}")
```

## 七、實作步驟

### 7.1 第一週：基礎架構
1. 設置事件總線 (EventBus)
2. 實作 Orchestrator Agent
3. 建立基礎 Agent 類別
4. 設置日誌系統

### 7.2 第二週：核心 Agent
1. 實作 Threat Intel Agent
2. 實作 Feature Designer Agent
3. 整合現有檢測引擎
4. 建立事件流程

### 7.3 第三週：自動化流程
1. 實作 Model Trainer Agent
2. 實作 Attack Simulator Agent
3. 建立端到端工作流
4. 添加監控儀表板

### 7.4 第四週：優化與測試
1. 性能優化
2. 錯誤處理
3. 安全加固
4. 文檔完善

## 八、擴展計劃

### 8.1 短期擴展 (1-3個月)
- 添加更多威脅情報源
- 實作模型漂移檢測
- 建立 CI/CD 管道
- 添加 Web 介面

### 8.2 中期擴展 (3-6個月)
- 實作分散式部署
- 添加機器學習模型
- 建立客戶回饋系統
- 實作合規檢查

### 8.3 長期擴展 (6-12個月)
- 實作多租戶支援
- 添加進階分析功能
- 建立生態系統整合
- 實作自動化決策

## 九、安全考量

### 9.1 資料安全
- 所有敏感資料加密存儲
- 事件傳輸使用 TLS
- 實作存取控制
- 定期安全審計

### 9.2 系統安全
- Agent 隔離執行
- 資源使用限制
- 異常行為檢測
- 自動化安全更新

## 十、結論

這個 MVP Agent 工作流設計為 RMDS 專案提供了：

1. **自動化威脅響應**: 從威脅發現到特徵部署的全自動化流程
2. **可擴展架構**: 基於事件的鬆耦合設計，易於擴展
3. **可觀測性**: 完整的監控和 KPI 系統
4. **安全優先**: 內建安全控制和資料保護
5. **漸進式實施**: 從 6 個核心 Agent 開始，逐步擴展

通過這個設計，您的 RMDS 系統將能夠：
- 自動響應新威脅
- 持續優化檢測能力
- 提供實時監控和警報
- 支援大規模部署
- 降低運營成本

建議從核心 Agent 開始實作，逐步建立完整的自動化工作流。
