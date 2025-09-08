#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試權限修復
"""

import fnmatch
import logging

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_permission_fix():
    """測試權限修復"""
    logger.info("測試權限修復...")
    
    # 測試案例
    test_cases = [
        ("include/detection_engine.hpp", "include/**/*.hpp"),
        ("src/detection_engine.cpp", "src/**/*.cpp"),
        ("src/memory_monitor.cpp", "src/**/*.cpp"),
        ("include/memory_detection_types.hpp", "include/**/*.hpp"),
        ("CMakeLists.txt", "CMakeLists.txt"),
        ("docs/README.md", "docs/**/*.md")
    ]
    
    for path, pattern in test_cases:
        logger.info(f"\n測試: {path} vs {pattern}")
        
        # 標準化路徑
        path_str = path.replace('\\', '/')
        
        # 處理 ** 模式
        if "**" in pattern:
            # 基本模式
            base_pattern = pattern.replace("**", "*")
            base_match = fnmatch.fnmatch(path_str, base_pattern)
            logger.info(f"  基本模式 {base_pattern}: {'✓' if base_match else '✗'}")
            
            # 直接模式
            parts = pattern.split("**")
            if len(parts) == 2:
                prefix = parts[0].rstrip("/")
                suffix = parts[1].lstrip("/")
                direct_pattern = f"{prefix}/{suffix}"
                direct_match = fnmatch.fnmatch(path_str, direct_pattern)
                logger.info(f"  直接模式 {direct_pattern}: {'✓' if direct_match else '✗'}")
                
                if base_match or direct_match:
                    logger.info(f"  ✓ 權限檢查通過")
                else:
                    logger.info(f"  ✗ 權限檢查失敗")
        else:
            # 簡單模式
            simple_match = fnmatch.fnmatch(path_str, pattern)
            logger.info(f"  簡單模式: {'✓' if simple_match else '✗'}")

if __name__ == "__main__":
    test_permission_fix()
