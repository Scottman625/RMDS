# Unified Diff 生成提示模板

## 基本要求

請僅輸出 unified diff 格式，**禁止任何自然語言說明**。格式必須嚴格遵循以下規範：

### 1. 文件頭格式
- 每個文件必須以 `diff --git a/文件路徑 b/文件路徑` 開頭
- 新增文件：`--- /dev/null`
- 刪除文件：`+++ /dev/null`
- 修改文件：`--- a/原文件 +++ b/新文件`

### 2. Hunk 格式
每個修改區塊必須包含：
```
@@ -舊起始行,舊行數 +新起始行,新行數 @@
```

### 3. 行前綴規則
- ` ` (空格)：未修改的行
- `+`：新增的行
- `-`：刪除的行

## 嚴格格式要求

1. **不要使用 Markdown code fence** (` ```diff `)
2. **不要添加任何說明文字**
3. **不要修改未被要求的文件**
4. **確保行數與 hunk 頭部宣告一致**
5. **不要包含尾隨空格**

## 示例格式

```
diff --git a/src/example.cpp b/src/example.cpp
index 1234567..abcdefg 100644
--- a/src/example.cpp
+++ b/src/example.cpp
@@ -1,3 +1,4 @@
 #include <iostream>
 #include <string>
+// 新增的註解
 void main() {
     std::cout << "Hello World" << std::endl;
 }
```

## 新增文件示例

```
diff --git a/src/new_file.cpp b/src/new_file.cpp
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/src/new_file.cpp
@@ -0,0 +1,5 @@
+#include <iostream>
+
+int main() {
+    return 0;
+}
```

## 刪除文件示例

```
diff --git a/src/old_file.cpp b/src/old_file.cpp
deleted file mode 100644
index 1234567..0000000
--- a/src/old_file.cpp
+++ /dev/null
@@ -1,5 +0,0 @@
-#include <iostream>
-
-int main() {
-    return 0;
-}
```

## 錯誤避免

1. **路徑安全**：不要使用 `../` 或絕對路徑
2. **行數一致**：確保 hunk 中的行數與頭部宣告匹配
3. **上下文完整**：包含足夠的上下文行
4. **格式正確**：每個 `@@` 行必須有正確的格式

## 輸出要求

**只輸出 unified diff，不要任何其他文字！**
