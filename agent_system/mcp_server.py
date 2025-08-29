#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMDS Agent System - MCP Server
基於 Model Context Protocol 的安全代碼操作服務器
"""

import json
import os
import subprocess
import tempfile
import hashlib
import difflib
import logging
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import fnmatch
import shutil

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Policy:
    """權限策略配置"""
    write_allow: List[str]
    read_allow: List[str]
    deny: List[str]
    execute_allow: Optional[List[str]] = None
    max_patch_size: int = 1000  # 最大 patch 行數
    max_file_size_mb: int = 10  # 最大文件大小 (MB)
    timeout_seconds: int = 300  # 操作超時時間
    build_timeout_seconds: int = 600  # 編譯超時時間
    execution_timeout_seconds: int = 120  # 執行超時時間
    rate_limits: Optional[Dict[str, Any]] = None  # 速率限制
    security: Optional[Dict[str, Any]] = None  # 安全配置

@dataclass
class ActionResult:
    """操作結果"""
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    trace_id: str = None
    timestamp: str = None

class MCPServer:
    """MCP 服務器"""
    
    def __init__(self, repo_root: str, policy_file: str = "policy.json"):
        self.repo_root = Path(repo_root).resolve()
        self.policy = self._load_policy(policy_file)
        self.action_log = []
        
        # 確保在正確的目錄
        if not self.repo_root.exists():
            raise ValueError(f"Repository root does not exist: {self.repo_root}")
        
        logger.info(f"MCP Server initialized with repo root: {self.repo_root}")
        logger.info(f"Policy loaded: {asdict(self.policy)}")
    
    def _load_policy(self, policy_file: str) -> Policy:
        """載入權限策略"""
        try:
            if os.path.exists(policy_file):
                with open(policy_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                # 默認策略
                data = {
                    "write_allow": [
                        "src/**/*.cpp",
                        "src/**/*.hpp", 
                        "src/*.cpp",        # 額外補上零層級
                        "src/*.hpp",
                        "include/**/*.hpp",
                        "include/*.hpp",
                        "tests/**/*.cpp",
                        "tests/**/*.hpp",
                        "tests/*.cpp",
                        "tests/*.hpp",
                        "CMakeLists.txt",
                        "build/**/*"
                    ],
                    "read_allow": [
                        "src/**/*",
                        "include/**/*",
                        "tests/**/*",
                        "CMakeLists.txt",
                        "README.md",
                        "docs/**/*",
                        "build/**/*"
                    ],
                    "execute_allow": [
                        "build/**/*.exe",
                        "build/**/*.out",
                        "build/src/**/*.exe",
                        "build/tests/**/*.exe"
                    ],
                    "deny": [
                        "secrets/**",
                        ".env*",
                        "*.key",
                        "*.pem",
                        ".git/**",
                        "logs/**",
                        "*.log"
                    ],
                    "build_timeout_seconds": 600,
                    "execution_timeout_seconds": 120,
                    "rate_limits": {
                        "apply_patch_per_hour": 10,
                        "read_file_per_minute": 60,
                        "run_tests_per_hour": 5,
                        "build_per_hour": 3,
                        "execute_per_hour": 10
                    },
                    "security": {
                        "require_dry_run_first": True,
                        "max_concurrent_operations": 3,
                        "audit_all_operations": True,
                        "allow_build_operations": True,
                        "allow_execution": True,
                        "execution_sandbox": True
                    }
                }
            
            return Policy(**data)
        
        except Exception as e:
            logger.error(f"Failed to load policy: {e}")
            raise
    
    def _generate_trace_id(self) -> str:
        """生成追蹤 ID"""
        return f"trace_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    
    def _setup_visual_studio_env(self) -> dict:
        """設置 Visual Studio 環境變數"""
        import os
        import subprocess
        
        # 複製當前環境
        env = os.environ.copy()
        
        # 查找 Visual Studio 安裝路徑
        vs_paths = [
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat"
        ]
        
        for vs_path in vs_paths:
            if Path(vs_path).exists():
                try:
                    # 執行 vcvars64.bat 並捕獲環境變數
                    result = subprocess.run(
                        [vs_path, "&&", "set"],
                        shell=True,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        # 解析環境變數
                        for line in result.stdout.split('\n'):
                            if '=' in line:
                                key, value = line.split('=', 1)
                                env[key.strip()] = value.strip()
                        
                        logger.info(f"Visual Studio 環境已設置: {vs_path}")
                        return env
                except Exception as e:
                    logger.warning(f"設置 Visual Studio 環境失敗: {e}")
                    continue
        
        logger.warning("未找到 Visual Studio 環境，使用默認環境")
        return env
    
    def _log_action(self, action_name: str, params: Dict, result: ActionResult):
        """記錄操作日誌"""
        log_entry = {
            "timestamp": time.time(),
            "action": action_name,
            "params": params,
            "result": asdict(result),
            "trace_id": result.trace_id
        }
        self.action_log.append(log_entry)
        
        # 寫入日誌文件
        log_file = self.repo_root / "logs" / "mcp_actions.log"
        log_file.parent.mkdir(exist_ok=True)
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def _check_permission(self, path: str, operation: str) -> bool:
        """檢查權限"""
        try:
            # 標準化路徑分隔符
            path_str = path.replace('\\', '/')
            
            # 檢查拒絕列表
            for pattern in self.policy.deny:
                if fnmatch.fnmatch(path_str, pattern):
                    logger.warning(f"Access denied: {path_str} matches deny pattern {pattern}")
                    return False
            
            # 檢查讀取權限
            if operation == "read":
                for pattern in self.policy.read_allow:
                    if fnmatch.fnmatch(path_str, pattern):
                        return True
                logger.warning(f"Read access denied: {path_str}")
                return False
            
            # 檢查寫入權限
            elif operation == "write":
                for pattern in self.policy.write_allow:
                    # 改用更直覺的 ** 規則：** 表示 0+ 層
                    # 將 pattern 轉換成正規表示式
                    regex = (pattern
                             .replace(".", r"\.")
                             .replace("**/", r"(.*/)?")
                             .replace("**", r".*")
                             .replace("*", r"[^/]*"))
                    import re
                    if re.fullmatch(regex, path_str):
                        return True
                logger.warning(f"Write access denied (no pattern match): {path_str}")
                return False
            
            # 檢查執行權限
            elif operation == "execute":
                if not self.policy.execute_allow:
                    logger.warning("Execute permissions not configured")
                    return False
                for pattern in self.policy.execute_allow:
                    if fnmatch.fnmatch(path_str, pattern):
                        return True
                logger.warning(f"Execute access denied: {path_str}")
                return False
            
            return False
        
        except Exception as e:
            logger.error(f"Permission check error: {e}")
            return False
    
    def _get_file_hash(self, file_path: Path) -> str:
        """獲取文件哈希值"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to get file hash: {e}")
            return ""
    
    def list_files(self, params: Dict[str, Any]) -> ActionResult:
        """列出文件"""
        trace_id = self._generate_trace_id()
        
        try:
            base_path = params.get("path", "src")
            glob_pattern = params.get("glob", "*")
            
            full_path = self.repo_root / base_path
            if not full_path.exists():
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Path does not exist: {base_path}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            files = []
            for file_path in full_path.rglob(glob_pattern):
                if file_path.is_file():
                    rel_path = str(file_path.relative_to(self.repo_root))
                    if self._check_permission(rel_path, "read"):
                        files.append({
                            "path": rel_path,
                            "size": file_path.stat().st_size,
                            "modified": file_path.stat().st_mtime
                        })
            
            result = ActionResult(
                success=True,
                data={"files": files, "count": len(files)},
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
            self._log_action("list_files", params, result)
            return result
        
        except Exception as e:
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("list_files", params, result)
            return result
    
    def read_file(self, params: Dict[str, Any]) -> ActionResult:
        """讀取文件"""
        trace_id = self._generate_trace_id()
        
        try:
            file_path = params["path"]
            
            if not self._check_permission(file_path, "read"):
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Read access denied: {file_path}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            full_path = self.repo_root / file_path
            
            # 檢查文件大小
            if full_path.stat().st_size > self.policy.max_file_size_mb * 1024 * 1024:
                return ActionResult(
                    success=False,
                    data={},
                    error=f"File too large: {file_path}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            file_hash = self._get_file_hash(full_path)
            
            result = ActionResult(
                success=True,
                data={
                    "path": file_path,
                    "content": content,
                    "hash": file_hash,
                    "size": len(content),
                    "lines": len(content.splitlines())
                },
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
            self._log_action("read_file", params, result)
            return result
        
        except Exception as e:
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("read_file", params, result)
            return result
    
    def apply_patch(self, params: Dict[str, Any]) -> ActionResult:
        """應用補丁"""
        trace_id = self._generate_trace_id()
        
        try:
            branch = params.get("branch", "master")
            patch_content = params["unified_diff"]
            dry_run = params.get("dry_run", True)
            commit_changes = params.get("commit", True)
            task_id = params.get("task_id", "unknown")
            
            # 擷取真正的 diff 區塊（防止 LLM 包裝文字）
            patch_content = self._extract_unified_diff(patch_content)
            if not patch_content:
                return ActionResult(
                    success=False,
                    data={},
                    error="No valid unified diff block found",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 檢查補丁大小
            patch_lines = len(patch_content.splitlines())
            if patch_lines > self.policy.max_patch_size:
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Patch too large: {patch_lines} lines (max: {self.policy.max_patch_size})",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 解析補丁中的文件路徑
            modified_files = []
            for line in patch_content.splitlines():
                if line.startswith("+++ b/"):
                    file_path = line[6:]
                    if not self._check_permission(file_path, "write"):
                        return ActionResult(
                            success=False,
                            data={},
                            error=f"Write access denied: {file_path}",
                            trace_id=trace_id,
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                    modified_files.append(file_path)
            
            if not modified_files:
                return ActionResult(
                    success=False,
                    data={},
                    error="Diff parsed but contains no modified files",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 切換到指定分支
            try:
                subprocess.run(
                    ["git", "checkout", branch],
                    cwd=self.repo_root,
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore',
                    timeout=self.policy.timeout_seconds
                )
            except subprocess.TimeoutExpired:
                return ActionResult(
                    success=False,
                    data={},
                    error="Git checkout timeout",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            except subprocess.CalledProcessError as e:
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Git checkout failed: {e.stderr}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            if dry_run:
                # 乾運行：檢查補丁是否可以應用
                try:
                    result = subprocess.run(
                        ["git", "apply", "--check", "-"],
                        cwd=self.repo_root,
                        input=patch_content,
                        text=True,
                        capture_output=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=self.policy.timeout_seconds
                    )
                    
                    if result.returncode == 0:
                        return ActionResult(
                            success=True,
                            data={
                                "dry_run": True,
                                "would_modify": modified_files,
                                "patch_size": patch_lines
                            },
                            trace_id=trace_id,
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                    else:
                        return ActionResult(
                            success=False,
                            data={},
                            error=f"Patch check failed: {result.stderr}",
                            trace_id=trace_id,
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                
                except subprocess.TimeoutExpired:
                    return ActionResult(
                        success=False,
                        data={},
                        error="Patch check timeout",
                        trace_id=trace_id,
                        timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                    )
            
            else:
                # 實際應用補丁
                try:
                    # 應用補丁
                    result = subprocess.run(
                        ["git", "apply", "-"],
                        cwd=self.repo_root,
                        input=patch_content,
                        text=True,
                        capture_output=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=self.policy.timeout_seconds
                    )
                    
                    if result.returncode != 0:
                        return ActionResult(
                            success=False,
                            data={},
                            error=f"Patch apply failed: {result.stderr}",
                            trace_id=trace_id,
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                    
                    commit_hash = None
                    if commit_changes:
                        # add + commit
                        subprocess.run(
                            ["git", "add"] + modified_files,
                            cwd=self.repo_root,
                            check=True,
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                            errors='ignore',
                            timeout=self.policy.timeout_seconds
                        )
                        
                        commit_message = f"Agent patch - {task_id} - {trace_id}"
                        subprocess.run(
                            ["git", "commit", "-m", commit_message],
                            cwd=self.repo_root,
                            check=True,
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                            errors='ignore',
                            timeout=self.policy.timeout_seconds
                        )
                        
                        commit_hash = subprocess.check_output(
                            ["git", "rev-parse", "HEAD"],
                            cwd=self.repo_root,
                            text=True,
                            encoding='utf-8',
                            errors='ignore',
                            timeout=self.policy.timeout_seconds
                        ).strip()
                    
                    return ActionResult(
                        success=True,
                        data={
                            "dry_run": False,
                            "modified": modified_files,
                            "commit": commit_changes,
                            "commit_hash": commit_hash,
                            "patch_size": patch_lines,
                            "patch_id": hashlib.sha256(patch_content.encode('utf-8')).hexdigest()[:16]
                        },
                        trace_id=trace_id,
                        timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                    )
                
                except subprocess.TimeoutExpired:
                    return ActionResult(
                        success=False,
                        data={},
                        error="Patch apply timeout",
                        trace_id=trace_id,
                        timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                    )
                except subprocess.CalledProcessError as e:
                    return ActionResult(
                        success=False,
                        data={},
                        error=f"Git operation failed: {e.stderr}",
                        trace_id=trace_id,
                        timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                    )
        
        except Exception as e:
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("apply_patch", params, result)
            return result

    def _extract_unified_diff(self, text: str) -> str:
        """從 LLM 回傳文字中擷取第一個合法 unified diff 區塊"""
        lines = text.splitlines()
        in_code = False
        buf = []
        candidates = []
        
        for i, line in enumerate(lines):
            low = line.strip().lower()
            if low.startswith("```"):
                if in_code:
                    in_code = False
                else:
                    # 進入 code block；不強制要求 diff 關鍵字，因 LLM 可能省略
                    in_code = True
                continue
            
            if line.startswith("--- ") and (" a/" in line or line.startswith("--- a/")):
                # 從這裡收集直到遇到空白區塊或文件結束
                block = [line]
                j = i + 1
                while j < len(lines):
                    if lines[j].startswith("--- ") and j != i:
                        break
                    block.append(lines[j])
                    j += 1
                candidates.append("\n".join(block))
        
        if candidates:
            # 取第一個
            return candidates[0]
        
        # 若沒找到，嘗試整段就是 diff
        if text.startswith("--- "):
            return text
        
        return ""
    
    def run_unit_tests(self, params: Dict[str, Any]) -> ActionResult:
        """運行單元測試"""
        trace_id = self._generate_trace_id()
        
        try:
            branch = params.get("branch", "master")
            coverage = params.get("coverage", True)
            
            # 切換分支
            subprocess.run(
                ["git", "checkout", branch],
                cwd=self.repo_root,
                check=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=self.policy.timeout_seconds
            )
            
            # 構建項目
            build_dir = self.repo_root / "build"
            build_dir.mkdir(exist_ok=True)
            
            subprocess.run(
                ["cmake", "..", "-DBUILD_TESTING=ON"],
                cwd=build_dir,
                check=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=self.policy.timeout_seconds
            )
            
            subprocess.run(
                ["make", "-j4"],
                cwd=build_dir,
                check=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=self.policy.timeout_seconds
            )
            
            # 運行測試
            test_cmd = ["ctest", "-j4", "--output-on-failure"]
            if coverage:
                test_cmd.extend(["--coverage", "--coverage-dir", "coverage"])
            
            result = subprocess.run(
                test_cmd,
                cwd=build_dir,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=self.policy.timeout_seconds
            )
            
            test_status = "pass" if result.returncode == 0 else "fail"
            
            # 收集覆蓋率信息
            coverage_data = {}
            if coverage and (build_dir / "coverage").exists():
                coverage_data = self._collect_coverage(build_dir / "coverage")
            
            return ActionResult(
                success=True,
                data={
                    "status": test_status,
                    "stdout": result.stdout[-4000:],  # 限制輸出大小
                    "stderr": result.stderr[-2000:],
                    "coverage": coverage_data
                },
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
        
        except Exception as e:
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("run_unit_tests", params, result)
            return result
    
    def run_static_analysis(self, params: Dict[str, Any]) -> ActionResult:
        """運行靜態分析"""
        trace_id = self._generate_trace_id()
        
        try:
            branch = params.get("branch", "master")
            tools = params.get("tools", ["clang-tidy", "cppcheck"])
            
            # 切換分支
            subprocess.run(
                ["git", "checkout", branch],
                cwd=self.repo_root,
                check=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=self.policy.timeout_seconds
            )
            
            issues = []
            
            # 運行 clang-tidy
            if "clang-tidy" in tools:
                clang_issues = self._run_clang_tidy()
                issues.extend(clang_issues)
            
            # 運行 cppcheck
            if "cppcheck" in tools:
                cppcheck_issues = self._run_cppcheck()
                issues.extend(cppcheck_issues)
            
            return ActionResult(
                success=True,
                data={
                    "issues": issues,
                    "total_issues": len(issues),
                    "tools_used": tools
                },
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
        
        except Exception as e:
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("run_static_analysis", params, result)
            return result
    
    def _run_clang_tidy(self) -> List[Dict[str, Any]]:
        """運行 clang-tidy"""
        issues = []
        try:
            # 查找所有 C++ 源文件
            cpp_files = list(self.repo_root.rglob("*.cpp")) + list(self.repo_root.rglob("*.hpp"))
            
            for cpp_file in cpp_files:
                if self._check_permission(str(cpp_file.relative_to(self.repo_root)), "read"):
                    result = subprocess.run(
                        ["clang-tidy", str(cpp_file), "--"],
                        cwd=self.repo_root,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=60
                    )
                    
                    if result.stdout:
                        for line in result.stdout.splitlines():
                            if "warning:" in line or "error:" in line:
                                # 解析 clang-tidy 輸出
                                parts = line.split(":")
                                if len(parts) >= 4:
                                    issues.append({
                                        "tool": "clang-tidy",
                                        "file": parts[0],
                                        "line": parts[1],
                                        "column": parts[2],
                                        "message": ":".join(parts[3:]).strip(),
                                        "severity": "warning" if "warning:" in line else "error"
                                    })
        
        except Exception as e:
            logger.error(f"clang-tidy error: {e}")
        
        return issues
    
    def _run_cppcheck(self) -> List[Dict[str, Any]]:
        """運行 cppcheck"""
        issues = []
        try:
            result = subprocess.run(
                ["cppcheck", "--enable=all", "--xml", "--xml-version=2", "src/", "include/"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=self.policy.timeout_seconds
            )
            
            # 解析 XML 輸出
            if result.stdout:
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(result.stdout)
                    for error in root.findall(".//error"):
                        issues.append({
                            "tool": "cppcheck",
                            "file": error.get("file", ""),
                            "line": error.get("line", ""),
                            "message": error.get("msg", ""),
                            "severity": error.get("severity", "style")
                        })
                except ET.ParseError:
                    logger.error("Failed to parse cppcheck XML output")
        
        except Exception as e:
            logger.error(f"cppcheck error: {e}")
        
        return issues
    
    def _collect_coverage(self, coverage_dir: Path) -> Dict[str, Any]:
        """收集覆蓋率數據"""
        coverage_data = {}
        try:
            # 這裡可以實現具體的覆蓋率收集邏輯
            # 例如解析 lcov 文件或 gcov 輸出
            coverage_data = {
                "total_lines": 0,
                "covered_lines": 0,
                "coverage_percentage": 0.0
            }
        except Exception as e:
            logger.error(f"Coverage collection error: {e}")
        
        return coverage_data
    
    def get_action_log(self, params: Dict[str, Any]) -> ActionResult:
        """獲取操作日誌"""
        trace_id = self._generate_trace_id()
        
        try:
            limit = params.get("limit", 100)
            action_filter = params.get("action", None)
            
            filtered_log = self.action_log
            if action_filter:
                filtered_log = [entry for entry in self.action_log if entry["action"] == action_filter]
            
            return ActionResult(
                success=True,
                data={
                    "log_entries": filtered_log[-limit:],
                    "total_entries": len(filtered_log)
                },
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
        
        except Exception as e:
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("get_action_log", params, result)
            return result
    
    def build_project(self, params: Dict[str, Any]) -> ActionResult:
        """編譯項目"""
        trace_id = self._generate_trace_id()
        
        try:
            # 檢查編譯權限
            if not self.policy.security.get("allow_build_operations", False):
                return ActionResult(
                    success=False,
                    data={},
                    error="Build operations not allowed by policy",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            build_type = params.get("build_type", "Release")
            target = params.get("target", "all")
            
            # 創建構建目錄
            build_dir = self.repo_root / "build"
            build_dir.mkdir(exist_ok=True)
            
            # 清理 CMake 緩存以避免平台衝突
            cmake_cache = build_dir / "CMakeCache.txt"
            cmake_files = build_dir / "CMakeFiles"
            if cmake_cache.exists():
                cmake_cache.unlink()
                logger.info("Removed existing CMakeCache.txt")
            if cmake_files.exists():
                import shutil
                shutil.rmtree(cmake_files)
                logger.info("Removed existing CMakeFiles directory")
            
            # 檢查 CMakeLists.txt 是否存在
            cmake_file = self.repo_root / "CMakeLists.txt"
            if not cmake_file.exists():
                return ActionResult(
                    success=False,
                    data={},
                    error="CMakeLists.txt not found",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 配置 CMake
            logger.info(f"Configuring CMake in {build_dir}")
            
            # 檢測作業系統和編譯器
            import platform
            import shutil
            is_windows = platform.system() == "Windows"
            
            # 檢查 CMake 是否可用
            if not shutil.which("cmake"):
                return ActionResult(
                    success=False,
                    data={},
                    error="CMake not found. Please install CMake first.",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 檢測 vcpkg 工具鏈
            vcpkg_toolchain = None
            if os.environ.get('VCPKG_ROOT'):
                vcpkg_toolchain = f"{os.environ['VCPKG_ROOT']}/scripts/buildsystems/vcpkg.cmake"
            elif Path("D:/vcpkg/scripts/buildsystems/vcpkg.cmake").exists():
                vcpkg_toolchain = "D:/vcpkg/scripts/buildsystems/vcpkg.cmake"
            
            # Windows 平台工具鏈選擇邏輯
            if is_windows:
                # 設置 Visual Studio 環境（用於 MSVC 和 ClangCL）
                vs_env = self._setup_visual_studio_env()
                
                # 檢測可用的編譯器
                clang_cl = shutil.which("clang-cl")
                raw_clangpp = shutil.which("clang++")
                
                def is_mingw_clang(path):
                    """檢測是否為 MinGW/llvm-mingw 版本的 clang++"""
                    if not path:
                        return False
                    p = str(Path(path)).lower()
                    return "mingw" in p or "llvm-mingw" in p or p.endswith("\\bin\\clang++.exe")
                
                # 工具鏈選擇邏輯
                if clang_cl:
                    # 方案 B: Visual Studio + ClangCL
                    cmake_args = [
                        "cmake", "..",
                        "-G", "Visual Studio 17 2022",
                        "-A", "x64",
                        "-T", "ClangCL",
                        f"-DCMAKE_BUILD_TYPE={build_type}"
                    ]
                    active_mode = "clang-cl"
                    env = vs_env
                    logger.info("使用 Visual Studio + ClangCL 工具鏈")
                    
                elif raw_clangpp and is_mingw_clang(raw_clangpp):
                    # 方案 C: MinGW/llvm-mingw 模式
                    if shutil.which("ninja"):
                        generator = "Ninja"
                    else:
                        generator = "MinGW Makefiles"
                    
                    cmake_args = [
                        "cmake", "..",
                        f"-G", generator,
                        f"-DCMAKE_BUILD_TYPE={build_type}",
                        "-DCMAKE_C_COMPILER=clang",
                        "-DCMAKE_CXX_COMPILER=clang++"
                    ]
                    active_mode = "mingw-clang"
                    env = os.environ.copy()
                    logger.info(f"使用 {generator} + MinGW Clang 工具鏈")
                    
                else:
                    # 方案 A: 純 MSVC
                    cmake_args = [
                        "cmake", "..",
                        "-G", "Visual Studio 17 2022",
                        "-A", "x64",
                        f"-DCMAKE_BUILD_TYPE={build_type}"
                    ]
                    active_mode = "msvc"
                    env = vs_env
                    logger.info("使用 Visual Studio + MSVC 工具鏈")
                
                # 添加 vcpkg 工具鏈（如果可用）
                if vcpkg_toolchain:
                    cmake_args.append(f"-DCMAKE_TOOLCHAIN_FILE={vcpkg_toolchain}")
                    logger.info(f"使用 vcpkg 工具鏈: {vcpkg_toolchain}")
                
            else:
                # Linux/macOS 平台
                cmake_args = [
                    "cmake", "..",
                    f"-DCMAKE_BUILD_TYPE={build_type}",
                    "-DCMAKE_C_COMPILER=clang",
                    "-DCMAKE_CXX_COMPILER=clang++"
                ]
                active_mode = "linux-clang"
                env = os.environ.copy()
                logger.info("使用 Linux/macOS + Clang 工具鏈")
            
            # 執行 CMake 配置
            cmake_result = subprocess.run(
                cmake_args,
                cwd=build_dir,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=self.policy.build_timeout_seconds,
                env=env
            )
            
            if cmake_result.returncode != 0:
                error_msg = f"CMake configuration failed: {cmake_result.stderr}"
                if not cmake_result.stderr:
                    error_msg = f"CMake configuration failed with return code {cmake_result.returncode}. stdout: {cmake_result.stdout[-500:]}"
                return ActionResult(
                    success=False,
                    data={},
                    error=error_msg,
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 編譯項目
            logger.info(f"Building project with target: {target} (mode: {active_mode})")
            
            # 根據工具鏈模式選擇編譯命令
            if is_windows and active_mode in ["msvc", "clang-cl"]:
                # Visual Studio 生成器使用 cmake --build
                if target == "all":
                    build_result = subprocess.run(
                        ["cmake", "--build", ".", "--config", build_type, "--parallel"],
                        cwd=build_dir,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=self.policy.build_timeout_seconds,
                        env=env
                    )
                else:
                    build_result = subprocess.run(
                        ["cmake", "--build", ".", "--target", target, "--config", build_type],
                        cwd=build_dir,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=self.policy.build_timeout_seconds,
                        env=env
                    )
            else:
                # Ninja 或其他生成器
                if target == "all":
                    build_result = subprocess.run(
                        ["cmake", "--build", ".", "--config", build_type],
                        cwd=build_dir,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=self.policy.build_timeout_seconds,
                        env=env
                    )
                else:
                    build_result = subprocess.run(
                        ["cmake", "--build", ".", "--target", target, "--config", build_type],
                        cwd=build_dir,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=self.policy.build_timeout_seconds,
                        env=env
                    )
            
            if build_result.returncode != 0:
                error_msg = f"Build failed: {build_result.stderr}"
                if not build_result.stderr:
                    error_msg = f"Build failed with return code {build_result.returncode}. stdout: {build_result.stdout[-500:]}"
                return ActionResult(
                    success=False,
                    data={},
                    error=error_msg,
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 查找編譯後的文件
            executables = []
            for pattern in ["*.exe", "*.out", "*.so", "*.dll", "*.dylib"]:
                for exe_file in build_dir.rglob(pattern):
                    if exe_file.is_file():
                        rel_path = str(exe_file.relative_to(self.repo_root))
                        executables.append({
                            "path": rel_path,
                            "size": exe_file.stat().st_size,
                            "executable": True
                        })
            
            result = ActionResult(
                success=True,
                data={
                    "build_type": build_type,
                    "target": target,
                    "build_dir": str(build_dir),
                    "toolchain_mode": active_mode,
                    "executables": executables,
                    "cmake_output": cmake_result.stdout[-1000:],
                    "build_output": build_result.stdout[-2000:]
                },
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
            self._log_action("build_project", params, result)
            return result
        
        except subprocess.TimeoutExpired:
            result = ActionResult(
                success=False,
                data={},
                error="Build timeout",
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("build_project", params, result)
            return result
        
        except Exception as e:
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("build_project", params, result)
            return result
    
    def execute_binary(self, params: Dict[str, Any]) -> ActionResult:
        """執行編譯後的文件"""
        trace_id = self._generate_trace_id()
        
        try:
            # 檢查執行權限
            if not self.policy.security.get("allow_execution", False):
                return ActionResult(
                    success=False,
                    data={},
                    error="Execution not allowed by policy",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            binary_path = params["path"]
            args = params.get("args", [])
            working_dir = params.get("working_dir", str(self.repo_root))
            input_data = params.get("input", None)
            
            # 檢查執行權限
            if not self._check_permission(binary_path, "execute"):
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Execute access denied: {binary_path}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            full_path = self.repo_root / binary_path
            if not full_path.exists():
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Binary not found: {binary_path}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 準備執行命令
            cmd = [str(full_path)] + args
            
            logger.info(f"Executing: {' '.join(cmd)}")
            
            # 執行文件
            exec_result = subprocess.run(
                cmd,
                cwd=working_dir,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                input=input_data,
                timeout=self.policy.execution_timeout_seconds
            )
            
            result = ActionResult(
                success=True,
                data={
                    "binary": binary_path,
                    "args": args,
                    "working_dir": working_dir,
                    "return_code": exec_result.returncode,
                    "stdout": exec_result.stdout,
                    "stderr": exec_result.stderr,
                    "execution_time": time.time()
                },
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
            self._log_action("execute_binary", params, result)
            return result
        
        except subprocess.TimeoutExpired:
            result = ActionResult(
                success=False,
                data={},
                error="Execution timeout",
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("execute_binary", params, result)
            return result
        
        except Exception as e:
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("execute_binary", params, result)
            return result

# 使用範例
def main():
    """主函數範例"""
    # 初始化 MCP 服務器
    server = MCPServer(repo_root=".")
    
    # 測試列出文件
    result = server.list_files({"path": "src", "glob": "*.cpp"})
    print(f"List files result: {result}")
    
    # 測試讀取文件
    result = server.read_file({"path": "src/detection_engine.cpp"})
    print(f"Read file result: {result.success}")
    
    # 測試乾運行補丁
    test_patch = """--- a/src/test.cpp
+++ b/src/test.cpp
@@ -1,3 +1,4 @@
 #include <iostream>
 
 int main() {
+    std::cout << "Hello from patch!" << std::endl;
     return 0;
 }
"""
    result = server.apply_patch({
        "branch": "main",
        "unified_diff": test_patch,
        "dry_run": True,
        "task_id": "test_task"
    })
    print(f"Apply patch result: {result}")

if __name__ == "__main__":
    main()
