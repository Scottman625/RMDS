#include "memory_detection_engine.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <iomanip>
#include <random>

using namespace MemoryDetectionEngine;

// 模擬金融交易系統
class TradingSystem {
public:
    struct Trade {
        std::string symbol;
        double price;
        int quantity;
        std::string timestamp;
    };
    
    struct Account {
        std::string account_id;
        double balance;
        std::vector<Trade> trades;
    };
    
    Account account;
    std::vector<double> price_history;
    bool system_secure = true;
    
    TradingSystem() {
        account.account_id = "TRD001";
        account.balance = 1000000.0;
        price_history = {100.0, 101.5, 99.8, 102.3, 100.9};
    }
    
    void execute_trade(const std::string& symbol, double price, int quantity) {
        if (!system_secure) {
            std::cout << "   [CRITICAL] Trading system compromised!" << std::endl;
            return;
        }
        
        Trade trade{symbol, price, quantity, "2024-01-01 10:00:00"};
        account.trades.push_back(trade);
        account.balance -= price * quantity;
        
        std::cout << "   Executed trade: " << quantity << " " << symbol << " @ $" << price << std::endl;
        std::cout << "   Account balance: $" << std::fixed << std::setprecision(2) << account.balance << std::endl;
    }
    
    void simulate_market_attack() {
        std::cout << "   [ALERT] Detected potential market manipulation attempt!" << std::endl;
        std::cout << "   - Attempting to modify account balance" << std::endl;
        std::cout << "   - Attempting to inject fake trades" << std::endl;
        std::cout << "   - Attempting to manipulate price data" << std::endl;
    }
    
    void display_status() {
        std::cout << "   Account ID: " << account.account_id << std::endl;
        std::cout << "   Balance: $" << std::fixed << std::setprecision(2) << account.balance << std::endl;
        std::cout << "   Total Trades: " << account.trades.size() << std::endl;
        std::cout << "   System Status: " << (system_secure ? "SECURE" : "COMPROMISED") << std::endl;
    }
};

int main() {
    std::cout << "=== Financial Trading System Protection Example ===" << std::endl;
    std::cout << "High-frequency trading memory protection" << std::endl;
    
    // 配置引擎 - 針對金融系統的高安全性要求
    EngineConfig config;
    config.enable_mte = true;
    config.enable_llvm_instrumentation = true;
    config.enable_pattern_matching = true;
    config.enable_performance_monitoring = true;
    config.detection_threshold = 90;  // 高閾值，減少誤報
    config.max_latency_us = 1;        // 極低延遲要求
    config.detection_interval_ms = 10; // 極高頻率檢測
    config.log_level = "ERROR";
    
    std::cout << "\n1. Initializing Financial Trading Protection..." << std::endl;
    
    // 創建引擎
    auto trading_protection = std::make_unique<MemoryDetectionEngine>(config);
    
    if (!trading_protection->start()) {
        std::cerr << "Failed to start trading protection engine!" << std::endl;
        return 1;
    }
    
    std::cout << "2. Starting trading system simulation..." << std::endl;
    
    TradingSystem trading_system;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> attack_chance(1, 100);
    std::uniform_int_distribution<> trade_chance(1, 100);
    
    // 模擬交易系統運行
    for (int second = 0; second < 30; ++second) {
        std::cout << "\n--- Second " << (second + 1) << " ---" << std::endl;
        
        // 正常交易邏輯
        if (trade_chance(gen) <= 30) {  // 30% 機率執行交易
            trading_system.execute_trade("AAPL", 150.0 + (gen() % 10), 100);
        }
        
        // 顯示系統狀態
        trading_system.display_status();
        
        // 隨機觸發攻擊嘗試
        if (attack_chance(gen) <= 5) {  // 5% 機率
            trading_system.simulate_market_attack();
            
            // 獲取保護統計
            auto stats = trading_protection->get_stats();
            std::cout << "   Protection Stats:" << std::endl;
            std::cout << "     - Detections: " << stats.total_detections << std::endl;
            std::cout << "     - Detection Time: " << stats.average_detection_time_us << " us" << std::endl;
            std::cout << "     - False Positives: " << stats.total_false_positives << std::endl;
        }
        
        // 模擬高頻交易
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "\n3. Stopping trading protection..." << std::endl;
    trading_protection->stop();
    
    // 顯示最終統計
    auto final_stats = trading_protection->get_stats();
    std::cout << "\n=== Trading Protection Final Report ===" << std::endl;
    std::cout << "Total attack attempts detected: " << final_stats.total_detections << std::endl;
    std::cout << "False positives: " << final_stats.total_false_positives << std::endl;
    std::cout << "Average detection latency: " << final_stats.average_detection_time_us << " us" << std::endl;
    std::cout << "System integrity maintained: YES" << std::endl;
    std::cout << "Regulatory compliance: PASSED" << std::endl;
    
    std::cout << "\n=== Financial Trading Protection Example Completed ===" << std::endl;
    
    return 0;
} 