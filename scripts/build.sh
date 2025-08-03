#!/bin/bash

# 實時內存攻擊檢測引擎建置腳本

set -e

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 函數：打印帶顏色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 檢查依賴
check_dependencies() {
    print_info "檢查依賴..."
    
    # 檢查CMake
    if ! command -v cmake &> /dev/null; then
        print_error "CMake未找到，請安裝CMake 3.20或更高版本"
        exit 1
    fi
    
    # 檢查編譯器
    if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
        print_error "未找到C++編譯器，請安裝GCC或Clang"
        exit 1
    fi
    
    # 檢查LLVM
    if ! pkg-config --exists llvm; then
        print_warning "LLVM未找到，某些功能可能不可用"
    fi
    
    print_success "依賴檢查完成"
}

# 創建建置目錄
create_build_dir() {
    print_info "創建建置目錄..."
    mkdir -p build
    cd build
}

# 配置專案
configure_project() {
    print_info "配置專案..."
    
    local cmake_args="-DCMAKE_BUILD_TYPE=Release"
    
    # 檢查是否啟用測試
    if [ "$1" = "--with-tests" ]; then
        cmake_args="$cmake_args -DBUILD_TESTS=ON"
        print_info "啟用測試建置"
    fi
    
    # 檢查是否啟用範例
    if [ "$1" = "--with-examples" ] || [ "$2" = "--with-examples" ]; then
        cmake_args="$cmake_args -DBUILD_EXAMPLES=ON"
        print_info "啟用範例建置"
    fi
    
    cmake .. $cmake_args
    
    if [ $? -eq 0 ]; then
        print_success "專案配置成功"
    else
        print_error "專案配置失敗"
        exit 1
    fi
}

# 編譯專案
build_project() {
    print_info "編譯專案..."
    
    local jobs=$(nproc 2>/dev/null || echo 4)
    make -j$jobs
    
    if [ $? -eq 0 ]; then
        print_success "編譯成功"
    else
        print_error "編譯失敗"
        exit 1
    fi
}

# 運行測試
run_tests() {
    if [ "$1" = "--with-tests" ] || [ "$2" = "--with-tests" ]; then
        print_info "運行測試..."
        make test
        
        if [ $? -eq 0 ]; then
            print_success "測試通過"
        else
            print_error "測試失敗"
            exit 1
        fi
    fi
}

# 安裝
install_project() {
    if [ "$1" = "--install" ] || [ "$2" = "--install" ] || [ "$3" = "--install" ]; then
        print_info "安裝專案..."
        sudo make install
        
        if [ $? -eq 0 ]; then
            print_success "安裝成功"
        else
            print_error "安裝失敗"
            exit 1
        fi
    fi
}

# 清理
clean_build() {
    if [ "$1" = "--clean" ] || [ "$2" = "--clean" ] || [ "$3" = "--clean" ] || [ "$4" = "--clean" ]; then
        print_info "清理建置檔案..."
        make clean
        print_success "清理完成"
    fi
}

# 顯示幫助
show_help() {
    echo "實時內存攻擊檢測引擎建置腳本"
    echo ""
    echo "用法: $0 [選項]"
    echo ""
    echo "選項:"
    echo "  --with-tests     啟用測試建置"
    echo "  --with-examples  啟用範例建置"
    echo "  --install        安裝到系統"
    echo "  --clean          清理建置檔案"
    echo "  --help           顯示此幫助信息"
    echo ""
    echo "範例:"
    echo "  $0                    # 基本建置"
    echo "  $0 --with-tests       # 建置並運行測試"
    echo "  $0 --with-examples    # 建置範例"
    echo "  $0 --install          # 建置並安裝"
    echo "  $0 --clean            # 清理建置檔案"
}

# 主函數
main() {
    print_info "開始建置實時內存攻擊檢測引擎..."
    
    # 檢查幫助選項
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_help
        exit 0
    fi
    
    # 檢查依賴
    check_dependencies
    
    # 創建建置目錄
    create_build_dir
    
    # 配置專案
    configure_project "$@"
    
    # 編譯專案
    build_project
    
    # 運行測試
    run_tests "$@"
    
    # 安裝
    install_project "$@"
    
    # 清理
    clean_build "$@"
    
    print_success "建置完成！"
    print_info "可執行檔案位於: build/bin/"
    print_info "庫檔案位於: build/lib/"
}

# 執行主函數
main "$@" 