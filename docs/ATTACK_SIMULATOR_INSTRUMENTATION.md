# Attack Simulator Instrumentation Implementation

## Overview

This document describes the implementation of the "攻擊模擬器改造方案" (Attack Simulator Refactoring Plan) that transforms the attack simulator to generate RAW events that can be detected by the event-driven detection engine.

## Key Changes Implemented

### 1. Global Settings and Helper Functions

Added comprehensive instrumentation control parameters and helper functions:

```cpp
// === Instrumentation 控制參數 ===
#define ASM_USE_RW_TO_RX_TRANSITION   1      // 1: 先 RW 後 RX
#define ASM_USE_DOUBLE_STAGE          1      // 1: 兩階段寫入 (加強 Write 次數)
#define ASM_WRITE_SLEEP_MS            20     // 寫後到 VirtualProtect 的延遲 (測 RW→RX Gap)
#define ASM_SECOND_STAGE_SLEEP_MS     40     // 第二階段與最終保護切換間延遲
#define ASM_PROTECT_EXEC_MODE         0      // 0: PAGE_EXECUTE_READ, 1: PAGE_EXECUTE_READWRITE
#define ASM_PAD_SIGNATURE             1
#define ASM_SIGNATURE_TEXT            "SIMROP"
#define ASM_LOG_ADDR_PREFIX           "[SIMADDR]"  // 日誌標記，檢測器可以 grep
#define ASM_SCATTER_SEGMENTS_MAX      8
```

### 2. Helper Functions

#### `RWXBlock` Structure
```cpp
struct RWXBlock {
    void* base = nullptr;
    size_t size = 0;
    bool executable = false;
};
```

#### Core Helper Functions
- `allocate_rw_block()` - Allocates RW memory using `VirtualAlloc`
- `write_stage()` - Writes data using `WriteProcessMemory` (triggers WRITE_PROCESS_MEMORY events)
- `protect_exec()` - Changes protection to executable using `VirtualProtect` (triggers MEM_PROTECT_CHANGE events)
- `build_rop_block()` - Generates ROP gadgets and shellcode payloads
- `fmt_addr()` - Standardized 64-bit address formatting
- `sleep_ms()` - Configurable delays for testing gap detection

### 3. Modified Attack Functions

All attack functions now follow the standardized pattern:
1. **RW Allocation** → `VirtualAlloc(RW)`
2. **Write Stage(s)** → `WriteProcessMemory` (1-N times)
3. **Protection Change** → `VirtualProtect(RX/RWX)`

#### `simulate_rop_attack()`
- Uses `build_rop_block()` to generate realistic ROP gadgets
- Supports single-stage or double-stage writes (`ASM_USE_DOUBLE_STAGE`)
- Configurable RW→RX transition with gap testing
- Logs standardized addresses with `[SIMADDR]` prefix

#### `simulate_scattered_rop_attack()`
- Creates multiple memory segments (up to `ASM_SCATTER_SEGMENTS_MAX`)
- Each segment follows RW→Write→RX pattern
- Varying payload sizes and gadget configurations
- Individual RW→RX transitions for each segment

#### `simulate_heap_corruption()`
- Multiple pattern writes (DEADBEEF, BAADF00D, etc.)
- Staged writes with configurable delays
- Optional final RX protection
- High-density corruption patterns

#### `simulate_heap_corruption_with_shellcode()`
- Combines heap corruption patterns with shellcode
- Two-stage approach: corruption patterns + shellcode payload
- Configurable RW→RX transition

#### `simulate_realistic_rop_shellcode_attack()`
- Two-block approach: data block (RW) + exec block (RW→RX)
- Simulates real DEP bypass scenarios
- ROP chain + shellcode combination

### 4. Event Generation

The instrumented simulator now generates the following events that the detection engine can detect:

#### `WRITE_PROCESS_MEMORY` Events
- Triggered by `WriteProcessMemory()` calls in `write_stage()`
- Multiple writes per attack (staged approach)
- Configurable timing between writes

#### `MEM_PROTECT_CHANGE` Events
- Triggered by `VirtualProtect()` calls in `protect_exec()`
- RW→RX transitions for shellcode detection
- Configurable timing for gap analysis

#### `VirtualAlloc` Events
- Triggered by `VirtualAlloc()` calls in `allocate_rw_block()`
- RW memory allocation for attack payloads

### 5. Logging and Correlation

#### Standardized Address Formatting
```cpp
static inline std::string fmt_addr(const void* p) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setfill('0')
        << std::setw(16) << (uintptr_t)p;
    return oss.str();
}
```

#### Correlation Prefix
- All attack-related logs use `[SIMADDR]` prefix
- Detection engine can grep for this prefix to correlate events
- Standardized format: `[SIMADDR] TYPE base=0x... size=...`

#### Dual Logging
- Logs to both `logs/simple_attack_simulator.log` and `logs/detection_engine.log`
- Enables correlation between simulator and detection engine

### 6. Main Menu Integration

Updated main menu to indicate instrumented mode:
```
[Instrumented Mode] 所有攻擊將觸發 WriteProcessMemory + VirtualProtect 事件
```

## Configuration Options

### Timing Control
- `ASM_WRITE_SLEEP_MS` - Delay between write and protect (default: 20ms)
- `ASM_SECOND_STAGE_SLEEP_MS` - Delay for second stage (default: 40ms)

### Attack Behavior
- `ASM_USE_RW_TO_RX_TRANSITION` - Enable/disable RW→RX transitions
- `ASM_USE_DOUBLE_STAGE` - Enable/disable staged writes
- `ASM_PROTECT_EXEC_MODE` - RX (0) vs RWX (1) protection

### Detection Features
- `ASM_PAD_SIGNATURE` - Add "SIMROP" signature to payloads
- `ASM_SCATTER_SEGMENTS_MAX` - Maximum segments for scattered attacks

## Expected Detection Engine Integration

The detection engine should now be able to detect these attacks through:

1. **Gap Analysis** - RW→RX transitions within configurable time windows
2. **Pattern Recognition** - ROP gadgets, shellcode signatures, heap corruption patterns
3. **Event Correlation** - Multiple WRITE_PROCESS_MEMORY events followed by MEM_PROTECT_CHANGE
4. **Address Tracking** - Standardized address logging for correlation

## Testing

To test the instrumented simulator:

1. **Compile**: `g++ -std=c++14 -O2 -Wall -Wextra -Iinclude src/attack_simulator.cpp -o build/attack_simulator.exe -lpsapi`
2. **Run**: `./build/attack_simulator.exe`
3. **Monitor**: Check `logs/detection_engine.log` for `[SIMADDR]` entries
4. **Correlate**: Detection engine should trigger alerts based on event patterns

## Benefits

1. **Realistic Attack Simulation** - Attacks now follow real-world patterns
2. **Event-Driven Detection** - Generates events that modern detection engines expect
3. **Configurable Testing** - Adjustable timing and behavior for different test scenarios
4. **Correlation Support** - Standardized logging for easy event correlation
5. **Gap Analysis Testing** - Configurable delays for testing detection engine gap rules

## Future Enhancements

1. **Additional Attack Types** - More sophisticated attack patterns
2. **Dynamic Configuration** - Runtime configuration changes
3. **Performance Metrics** - Attack timing and success rate tracking
4. **Integration Testing** - Automated testing with detection engine
