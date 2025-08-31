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
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
import fnmatch
import shutil
import re

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

@dataclass
class PatchHunk:
    """表示一個 diff hunk"""
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    lines: List[str] = field(default_factory=list)  # 原始帶前綴的行

@dataclass
class FilePatch:
    """表示一個文件的 patch"""
    old_path: str
    new_path: str
    status: str  # modified|new|deleted|renamed
    hunks: List[PatchHunk] = field(default_factory=list)
    header_lines: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class DiffMeta:
    """diff 元數據"""
    raw: str
    normalized: str
    files: List[Dict[str, Any]]
    issues: List[str]
    valid: bool
    patch_id: Optional[str]

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
                    # 將 pattern 轉換成正規表示式以支持 ** 模式
                    regex = (pattern
                             .replace(".", r"\.")
                             .replace("**/", r"(.*/)?")
                             .replace("**", r".*")
                             .replace("*", r"[^/]*"))
                    if re.fullmatch(regex, path_str):
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
                    # 將 pattern 轉換成正規表示式以支持 ** 模式
                    regex = (pattern
                             .replace(".", r"\.")
                             .replace("**/", r"(.*/)?")
                             .replace("**", r".*")
                             .replace("*", r"[^/]*"))
                    if re.fullmatch(regex, path_str):
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
    
    def write_file(self, params: Dict[str, Any]) -> ActionResult:
        """寫入文件"""
        trace_id = self._generate_trace_id()
        logger.info(f"[WRITE_FILE] Starting file write, trace_id: {trace_id}")
        
        try:
            file_path = params["path"]
            content = params["content"]
            create_dirs = params.get("create_dirs", True)
            mode = params.get("mode", "overwrite")  # "overwrite", "append", "prepend"
            
            logger.info(f"[WRITE_FILE] Parameters: path={file_path}, content_length={len(content)}, create_dirs={create_dirs}, mode={mode}")
            
            if not self._check_permission(file_path, "write"):
                logger.error(f"[WRITE_FILE] Write access denied for: {file_path}")
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Write access denied: {file_path}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            full_path = self.repo_root / file_path
            
            # 檢查文件大小限制
            if len(content) > self.policy.max_file_size_mb * 1024 * 1024:
                logger.error(f"[WRITE_FILE] Content too large: {len(content)} bytes (max: {self.policy.max_file_size_mb}MB)")
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Content too large: {len(content)} bytes (max: {self.policy.max_file_size_mb}MB)",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 創建目錄（如果需要）
            if create_dirs:
                logger.info(f"[WRITE_FILE] Creating directories for: {full_path.parent}")
                full_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 根據模式決定如何寫入文件
            file_exists = full_path.exists()
            final_content = content
            
            if file_exists and mode != "overwrite":
                # 讀取現有內容
                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        existing_content = f.read()
                    
                    if mode == "append":
                        final_content = existing_content + "\n" + content
                        logger.info(f"[WRITE_FILE] Appending content to existing file")
                    elif mode == "prepend":
                        final_content = content + "\n" + existing_content
                        logger.info(f"[WRITE_FILE] Prepending content to existing file")
                    else:
                        logger.warning(f"[WRITE_FILE] Unknown mode '{mode}', using overwrite")
                        final_content = content
                except Exception as e:
                    logger.warning(f"[WRITE_FILE] Could not read existing file: {e}, using overwrite")
                    final_content = content
            else:
                logger.info(f"[WRITE_FILE] Writing content to {'existing' if file_exists else 'new'} file")
            
            # 寫入文件
            logger.info(f"[WRITE_FILE] Writing content to: {full_path}")
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(final_content)
            
            # 獲取文件信息
            file_hash = self._get_file_hash(full_path)
            file_size = full_path.stat().st_size
            
            result = ActionResult(
                success=True,
                data={
                    "path": file_path,
                    "size": file_size,
                    "lines": len(final_content.splitlines()),
                    "hash": file_hash,
                    "created": not file_exists,
                    "mode": mode,
                    "original_size": len(content) if mode != "overwrite" else None
                },
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
            self._log_action("write_file", params, result)
            return result
        
        except Exception as e:
            logger.error(f"[WRITE_FILE] Unexpected error: {e}")
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("write_file", params, result)
            return result

    def apply_diff(self, params: Dict[str, Any]) -> ActionResult:
        """應用 diff 變更到文件（不會覆蓋整個文件）"""
        trace_id = self._generate_trace_id()
        logger.info(f"[APPLY_DIFF] Starting diff application, trace_id: {trace_id}")
        
        try:
            file_path = params["path"]
            diff_content = params["diff_content"]
            
            logger.info(f"[APPLY_DIFF] Parameters: path={file_path}, diff_length={len(diff_content)}")
            
            if not self._check_permission(file_path, "write"):
                logger.error(f"[APPLY_DIFF] Write access denied for: {file_path}")
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Write access denied: {file_path}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            full_path = self.repo_root / file_path
            
            # 讀取原始文件內容
            if not full_path.exists():
                logger.error(f"[APPLY_DIFF] File does not exist: {file_path}")
                return ActionResult(
                    success=False,
                    data={},
                    error=f"File does not exist: {file_path}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    original_content = f.read()
                logger.info(f"[APPLY_DIFF] Read original file, length: {len(original_content)}")
            except Exception as e:
                logger.error(f"[APPLY_DIFF] Could not read original file: {e}")
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Could not read original file: {e}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 解析 diff 內容並應用變更
            original_lines = original_content.splitlines()
            new_lines = original_lines.copy()
            
            # 改進的 diff 應用邏輯
            diff_lines = diff_content.splitlines()
            line_number = 0
            in_hunk = False
            
            for line in diff_lines:
                if line.startswith('@@'):
                    # 解析 hunk 頭部
                    in_hunk = True
                    try:
                        # 簡單的 hunk 解析
                        parts = line.split()
                        if len(parts) >= 3:
                            # 提取行號信息
                            line_info = parts[1]
                            if line_info.startswith('-') and ',' in line_info:
                                line_number = int(line_info[1:].split(',')[0]) - 1
                                logger.info(f"[APPLY_DIFF] Found hunk at line {line_number}")
                            else:
                                # 如果沒有明確的行號，嘗試通過上下文匹配找到正確位置
                                logger.warning(f"[APPLY_DIFF] No explicit line number in hunk header, attempting context matching")
                                line_number = self._find_context_match_line(original_lines, diff_lines)
                                logger.info(f"[APPLY_DIFF] Context matching found line {line_number}")
                    except Exception as e:
                        logger.warning(f"[APPLY_DIFF] Could not parse hunk header: {e}")
                        # 嘗試通過上下文匹配找到正確位置
                        line_number = self._find_context_match_line(original_lines, diff_lines)
                        logger.info(f"[APPLY_DIFF] Context matching found line {line_number}")
                        continue
                elif in_hunk and line.startswith('+') and not line.startswith('++'):
                    # 添加新行
                    if line_number < len(new_lines):
                        new_lines.insert(line_number, line[1:])
                        logger.debug(f"[APPLY_DIFF] Added line at position {line_number}: {line[1:]}")
                    else:
                        new_lines.append(line[1:])
                        logger.debug(f"[APPLY_DIFF] Added line at end: {line[1:]}")
                    line_number += 1
                elif in_hunk and line.startswith('-') and not line.startswith('--'):
                    # 移除行
                    if line_number < len(new_lines):
                        removed_line = new_lines.pop(line_number)
                        logger.debug(f"[APPLY_DIFF] Removed line at position {line_number}: {removed_line}")
                    # 不增加 line_number，因為我們移除了這一行
                elif in_hunk and line.startswith(' '):
                    # 上下文行，跳過
                    line_number += 1
                    logger.debug(f"[APPLY_DIFF] Skipped context line at position {line_number-1}")
                elif not line.startswith('@'):
                    # 其他行，跳過
                    if in_hunk:
                        line_number += 1
            
            # 寫入修改後的文件
            final_content = '\n'.join(new_lines)
            
            # 檢查文件大小限制
            if len(final_content) > self.policy.max_file_size_mb * 1024 * 1024:
                logger.error(f"[APPLY_DIFF] Final content too large: {len(final_content)} bytes")
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Final content too large: {len(final_content)} bytes",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 寫入文件
            logger.info(f"[APPLY_DIFF] Writing modified content to: {full_path}")
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(final_content)
            
            # 獲取文件信息
            file_hash = self._get_file_hash(full_path)
            file_size = full_path.stat().st_size
            
            result = ActionResult(
                success=True,
                data={
                    "path": file_path,
                    "original_size": len(original_content),
                    "new_size": file_size,
                    "original_lines": len(original_lines),
                    "new_lines": len(new_lines),
                    "hash": file_hash,
                    "changes_applied": True
                },
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
            self._log_action("apply_diff", params, result)
            return result
        
        except Exception as e:
            logger.error(f"[APPLY_DIFF] Unexpected error: {e}")
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("apply_diff", params, result)
            return result

    def _find_context_match_line(self, original_lines, diff_lines):
        """通過上下文匹配找到正確的行號"""
        try:
            # 尋找 diff 中的上下文行（以空格開頭的行）
            context_lines = []
            for line in diff_lines:
                if line.startswith(' ') and not line.startswith('@@'):
                    context_lines.append(line[1:])  # 移除前導空格
            
            if not context_lines:
                logger.warning("[APPLY_DIFF] No context lines found, using line 0")
                return 0
            
            # 在原始文件中尋找匹配的上下文
            for i in range(len(original_lines)):
                # 檢查從第i行開始是否匹配上下文
                if i + len(context_lines) <= len(original_lines):
                    match = True
                    for j, context_line in enumerate(context_lines):
                        if original_lines[i + j].strip() != context_line.strip():
                            match = False
                            break
                    
                    if match:
                        logger.info(f"[APPLY_DIFF] Found context match at line {i}")
                        return i
            
            # 如果沒有找到完全匹配，嘗試部分匹配
            for i in range(len(original_lines)):
                for context_line in context_lines:
                    if context_line.strip() in original_lines[i]:
                        logger.info(f"[APPLY_DIFF] Found partial context match at line {i}")
                        return i
            
            # 如果還是沒有找到，返回一個合理的默認值
            logger.warning("[APPLY_DIFF] No context match found, using line 0")
            return 0
            
        except Exception as e:
            logger.error(f"[APPLY_DIFF] Error in context matching: {e}")
            return 0
    
    def apply_patch(self, params: Dict[str, Any]) -> ActionResult:
        """應用補丁"""
        trace_id = self._generate_trace_id()
        logger.info(f"[APPLY_PATCH] Starting patch application, trace_id: {trace_id}")
        
        try:
            patch_content = params.get("unified_diff", "")
            task_id = params.get("task_id", "unknown")
            dry_run = params.get("dry_run", True)
            commit_changes = params.get("commit", True)
            
            logger.info(f"[APPLY_PATCH] Parameters: dry_run={dry_run}, commit={commit_changes}")
            logger.info(f"[APPLY_PATCH] Patch content length: {len(patch_content)}")
            logger.debug(f"[APPLY_PATCH] Patch content: {patch_content[:500]}...")
            
            if not patch_content.strip():
                logger.error(f"[APPLY_PATCH] Empty patch content")
                return ActionResult(
                    success=False,
                    data={},
                    error="Empty patch content",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 使用新的強健 diff 解析和驗證
            diff_meta = self._extract_and_validate_unified_diff(patch_content, self.repo_root)
            logger.info(f"[APPLY_PATCH] Diff validation result: valid={diff_meta.valid}, issues={diff_meta.issues}")
            
            if not diff_meta.valid:
                logger.error(f"[APPLY_PATCH] Diff validation failed: {diff_meta.issues}")
                return ActionResult(
                    success=False,
                    data={},
                    error=f"Invalid diff: {'; '.join(diff_meta.issues)}",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            # 使用驗證後的標準化 diff
            patch_content = diff_meta.normalized
            patch_id = diff_meta.patch_id
            
            # 檢查文件權限
            modified_files = []
            for file_info in diff_meta.files:
                file_path = file_info.get("new_path", file_info.get("old_path", ""))
                if file_path and file_path != "/dev/null":
                    logger.info(f"[APPLY_PATCH] Checking write permission for: {file_path}")
                    if not self._check_permission(file_path, "write"):
                        logger.error(f"[APPLY_PATCH] Write access denied for: {file_path}")
                        return ActionResult(
                            success=False,
                            data={},
                            error=f"Write access denied: {file_path}",
                            trace_id=trace_id,
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                    modified_files.append(file_path)
            
            logger.info(f"[APPLY_PATCH] Files to be modified: {modified_files}")
            
            if not modified_files:
                logger.warning(f"[APPLY_PATCH] No files to modify found in diff")
                return ActionResult(
                    success=False,
                    data={},
                    error="No files to modify found in diff",
                    trace_id=trace_id,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            patch_lines = len(patch_content.splitlines())
            
            if dry_run:
                logger.info(f"[APPLY_PATCH] Performing dry run")
                # 乾運行檢查
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
                    
                    logger.info(f"[APPLY_PATCH] Dry run result: returncode={result.returncode}")
                    if result.stderr:
                        logger.debug(f"[APPLY_PATCH] Dry run stderr: {result.stderr}")
                    
                    if result.returncode == 0:
                        logger.info(f"[APPLY_PATCH] Dry run successful")
                        return ActionResult(
                            success=True,
                            data={
                                "dry_run": True,
                                "would_modify": modified_files,
                                "patch_size": patch_lines,
                                "patch_id": patch_id,
                                "diff_meta_issues": diff_meta.issues
                            },
                            trace_id=trace_id,
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                    else:
                        logger.error(f"[APPLY_PATCH] Dry run failed: {result.stderr}")
                        return ActionResult(
                            success=False,
                            data={},
                            error=f"Patch check failed: {result.stderr}",
                            trace_id=trace_id,
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                except subprocess.TimeoutExpired:
                    logger.error(f"[APPLY_PATCH] Dry run timeout")
                    return ActionResult(
                        success=False,
                        data={},
                        error="Patch check timeout",
                        trace_id=trace_id,
                        timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                    )
            else:
                logger.info(f"[APPLY_PATCH] Applying patch for real")
                # 實際應用補丁
                try:
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
                    
                    logger.info(f"[APPLY_PATCH] Apply result: returncode={result.returncode}")
                    if result.stderr:
                        logger.debug(f"[APPLY_PATCH] Apply stderr: {result.stderr}")
                    
                    if result.returncode != 0:
                        logger.error(f"[APPLY_PATCH] Patch apply failed: {result.stderr}")
                        return ActionResult(
                            success=False,
                            data={},
                            error=f"Patch apply failed: {result.stderr}",
                            trace_id=trace_id,
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                    
                    commit_hash = None
                    if commit_changes:
                        logger.info(f"[APPLY_PATCH] Committing changes")
                        # add + commit
                        try:
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
                            
                            logger.info(f"[APPLY_PATCH] Commit successful, hash: {commit_hash}")
                        except subprocess.CalledProcessError as e:
                            logger.error(f"[APPLY_PATCH] Git commit failed: {e}")
                            return ActionResult(
                                success=False,
                                data={},
                                error=f"Git commit failed: {e}",
                                trace_id=trace_id,
                                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                            )
                    
                    logger.info(f"[APPLY_PATCH] Patch application completed successfully")
                    return ActionResult(
                        success=True,
                        data={
                            "dry_run": False,
                            "modified": modified_files,
                            "commit": commit_changes,
                            "commit_hash": commit_hash,
                            "patch_size": patch_lines,
                            "patch_id": patch_id,
                            "diff_meta_issues": diff_meta.issues
                        },
                        trace_id=trace_id,
                        timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                    )
                except subprocess.TimeoutExpired:
                    logger.error(f"[APPLY_PATCH] Patch apply timeout")
                    return ActionResult(
                        success=False,
                        data={},
                        error="Patch apply timeout",
                        trace_id=trace_id,
                        timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                    )
        
        except Exception as e:
            logger.error(f"[APPLY_PATCH] Unexpected error: {e}")
            result = ActionResult(
                success=False,
                data={},
                error=str(e),
                trace_id=trace_id,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._log_action("apply_patch", params, result)
            return result

    def _extract_and_validate_unified_diff(self, text: str, workspace_root: Path) -> DiffMeta:
        """
        強健版 diff 提取與驗證
        
        回傳結構:
        {
          "raw": 原始抽取段,
          "normalized": 正規化後 diff (可能多檔),
          "files": [ FilePatch 序列化 ],
          "issues": [字串],
          "valid": bool,
          "patch_id": str
        }
        """
        raw = self._extract_all_diff_text(text)
        if not raw:
            return DiffMeta(
                raw="", 
                normalized="", 
                files=[], 
                issues=["ERR_NO_DIFF_FOUND"], 
                valid=False, 
                patch_id=None
            )
        
        files, issues = self._parse_unified_diff(raw)
        validate_issues = self._validate_file_patches(files, workspace_root)
        issues.extend(validate_issues)
        
        normalized = self._rebuild_unified_diff(files)
        patch_id = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
        
        return DiffMeta(
            raw=raw,
            normalized=normalized,
            files=[self._serialize_file_patch(fp) for fp in files],
            issues=issues,
            valid=len([i for i in issues if i.startswith("ERR_")]) == 0 and len(files) > 0,
            patch_id=patch_id
        )
    
    def _extract_all_diff_text(self, text: str) -> str:
        """
        1) 優先於 code fence (```...``` 或 ```diff) 中擷取 diff
        2) 若無 fence，掃描整體
        支援多檔案 diff --git or ---/+++ 組合
        """
        lines = text.splitlines()
        
        # 收集所有候選
        code_blocks = []
        in_block = False
        block_lang = ""
        current = []
        
        for line in lines:
            m = re.match(r"^```(\w+)?\s*$", line.strip())
            if m:
                if in_block:
                    # 結束
                    if current:
                        code_blocks.append((block_lang.lower(), "\n".join(current)))
                    in_block = False
                    current = []
                    block_lang = ""
                else:
                    in_block = True
                    block_lang = (m.group(1) or "").lower()
                continue
            
            if in_block:
                current.append(line.rstrip("\r"))
        
        # 優先在語言為 diff/patch 的 block
        for lang, content in code_blocks:
            if lang in ("diff", "patch"):
                if ("--- " in content and "+++" in content):
                    return content
        
        # 再次嘗試所有 block
        for _, content in code_blocks:
            if ("--- " in content and "+++" in content):
                return content
        
        # 無 code fence → 全文掃描：擷取從第一個 '--- a/' 或 'diff --git' 到文末
        pattern_idx = None
        for i, line in enumerate(lines):
            if line.startswith("diff --git ") or (line.startswith("--- ") and " a/" in line):
                pattern_idx = i
                break
        
        if pattern_idx is not None:
            return "\n".join(l.rstrip("\r") for l in lines[pattern_idx:])
        
        return ""
    
    def _parse_unified_diff(self, raw: str) -> Tuple[List[FilePatch], List[str]]:
        """解析 unified diff 格式"""
        files = []
        issues = []
        lines = raw.splitlines()
        i = 0
        current = None
        hunk = None
        hunk_header_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
        diff_git_re = re.compile(r"^diff --git a/(.+) b/(.+)")
        
        while i < len(lines):
            line = lines[i]
            
            if diff_git_re.match(line):
                m = diff_git_re.match(line)
                if current:
                    files.append(current)
                old_p, new_p = m.group(1), m.group(2)
                current = FilePatch(old_path=old_p, new_path=new_p, status="modified", header_lines=[line], hunks=[])
                hunk = None
                i += 1
                continue
            
            if line.startswith("--- "):
                # 可能沒有 diff --git 的簡化形式
                if current:
                    # 若還沒收集到 ---/+++ 對，上一 file 已結束
                    if current.hunks or current.header_lines:
                        files.append(current)
                
                path_part = line[4:].strip()
                old_p = path_part[2:] if path_part.startswith("a/") else path_part
                
                # 下一行應該 +++
                if i + 1 < len(lines) and lines[i+1].startswith("+++ "):
                    new_line = lines[i+1]
                    new_part = new_line[4:].strip()
                    new_p = new_part[2:] if new_part.startswith("b/") else new_part
                    current = FilePatch(old_path=old_p, new_path=new_p, status="modified", header_lines=[line, new_line], hunks=[])
                    i += 2
                    continue
                else:
                    issues.append(f"ERR_MALFORMED_HEADER at line {i+1}")
            
            if line.startswith("@@ "):
                if not current:
                    issues.append(f"ERR_ORPHAN_HUNK at line {i+1}")
                    i += 1
                    continue
                
                m = hunk_header_re.match(line)
                if not m:
                    issues.append(f"ERR_BAD_HUNK_HEADER line {i+1}")
                    i += 1
                    continue
                
                old_start = int(m.group(1))
                old_len = int(m.group(2) or "1")
                new_start = int(m.group(3))
                new_len = int(m.group(4) or "1")
                hunk = PatchHunk(old_start, old_len, new_start, new_len, [line])
                current.hunks.append(hunk)
                i += 1
                
                # 收集 hunk 內容直到下一個 @@ / 檔案邊界
                while i < len(lines):
                    l2 = lines[i]
                    if l2.startswith("@@ ") or l2.startswith("diff --git") or l2.startswith("--- "):
                        break
                    if l2 and l2[0] in ("+", "-", " "):
                        hunk.lines.append(l2)
                    elif l2 == r"\ No newline at end of file":
                        hunk.lines.append(l2)
                    else:
                        # 允許空行
                        hunk.lines.append(l2)
                    i += 1
                continue
            
            i += 1
        
        if current:
            files.append(current)
        
        # 狀態推斷：new file / deleted file
        for fp in files:
            if fp.old_path == "/dev/null":
                fp.status = "new"
            if fp.new_path == "/dev/null":
                fp.status = "deleted"
        
        return files, issues
    
    def _validate_file_patches(self, files: List[FilePatch], workspace_root: Path) -> List[str]:
        """驗證文件 patches"""
        issues = []
        
        for fp in files:
            # 路徑安全
            if not self._sanitize_diff_path(fp.old_path) or not self._sanitize_diff_path(fp.new_path):
                issues.append(f"ERR_UNSAFE_PATH:{fp.old_path}->{fp.new_path}")
                continue
            
            # 沒有 hunk
            if not fp.hunks and fp.status == "modified":
                issues.append(f"ERR_NO_HUNKS:{fp.old_path}")
            
            # 基本 hunk 行數檢查（不做全文比對，只檢計數）
            for h in fp.hunks:
                minus = sum(1 for l in h.lines[1:] if l.startswith("-"))
                plus = sum(1 for l in h.lines[1:] if l.startswith("+"))
                context = sum(1 for l in h.lines[1:] if l.startswith(" "))
                
                # old_len = minus + context
                # new_len = plus + context
                if (minus + context) != h.old_len or (plus + context) != h.new_len:
                    issues.append(f"WARN_LEN_MISMATCH:{fp.old_path}:{h.old_start}")
            
            # 上下文 spot 檢查（只檢第一行 context 作示例）
            if fp.status == "modified" and fp.old_path != "/dev/null":
                abs_path = workspace_root / fp.old_path
                if abs_path.exists():
                    try:
                        content = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                        for h in fp.hunks:
                            first_ctx = next((l[1:] for l in h.lines[1:] if l.startswith(" ")), None)
                            if first_ctx:
                                idx = h.old_start - 1
                                if idx < 0 or idx >= len(content) or content[idx].strip() != first_ctx.strip():
                                    issues.append(f"WARN_CONTEXT_MISMATCH:{fp.old_path}:{h.old_start}")
                    except Exception as ex:
                        issues.append(f"WARN_IO_READ:{fp.old_path}:{ex}")
                else:
                    if fp.status == "modified":
                        issues.append(f"ERR_FILE_NOT_FOUND:{fp.old_path}")
        
        return issues
    
    def _sanitize_diff_path(self, p: str) -> bool:
        """檢查路徑安全性"""
        if p in ("/dev/null",):
            return True
        if p.startswith("/") or p.startswith("\\"):
            return False
        if ".." in p:
            return False
        if any(c in p for c in ("\0", "\r")):
            return False
        return True
    
    def _rebuild_unified_diff(self, files: List[FilePatch]) -> str:
        """重建 unified diff"""
        out = []
        
        for fp in files:
            # 最佳化：加上 diff --git 行（如果缺）
            out.append(f"diff --git a/{fp.old_path} b/{fp.new_path}")
            
            if fp.status == "new":
                out.append("new file mode 100644")
            if fp.status == "deleted":
                out.append("deleted file mode 100644")
            
            out.append(f"--- {'/dev/null' if fp.status=='new' else 'a/'+fp.old_path}")
            out.append(f"+++ {'/dev/null' if fp.status=='deleted' else 'b/'+fp.new_path}")
            
            for h in fp.hunks:
                out.append(f"@@ -{h.old_start},{h.old_len} +{h.new_start},{h.new_len} @@")
                out.extend(h.lines[1:])  # 第一行是原始 hunk header 重新建構過了
        
        return "\n".join(out) + ("\n" if out else "")
    
    def _serialize_file_patch(self, fp: FilePatch) -> Dict[str, Any]:
        """序列化 FilePatch"""
        return {
            "old_path": fp.old_path,
            "new_path": fp.new_path,
            "status": fp.status,
            "hunks": [
                {
                    "old_start": h.old_start,
                    "old_len": h.old_len,
                    "new_start": h.new_start,
                    "new_len": h.new_len,
                    "line_count": len(h.lines)-1
                } for h in fp.hunks
            ]
        }
    
    # 保留舊方法作為向後兼容
    def _extract_unified_diff(self, text: str) -> str:
        """從 LLM 回傳文字中擷取第一個合法 unified diff 區塊（向後兼容）"""
        diff_meta = self._extract_and_validate_unified_diff(text, self.repo_root)
        return diff_meta.normalized if diff_meta.valid else ""
    
    def _clean_diff_format(self, diff_content: str) -> str:
        """清理 diff 格式，移除尾隨空格等問題（向後兼容）"""
        # 使用新的解析和重建方法
        files, _ = self._parse_unified_diff(diff_content)
        return self._rebuild_unified_diff(files)
    
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
