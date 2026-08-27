#!/bin/bash
# 教务管理系统 - 一键启动脚本（macOS / Linux）

cd "$(dirname "$0")"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo "========================================"
echo "   教务管理系统 - 启动中..."
echo "========================================"
echo ""

# 检查 Python
PYTHON=""
if command -v python3 &> /dev/null; then
    PYTHON=python3
elif command -v python &> /dev/null; then
    PYTHON=python
else
    echo "❌ 未检测到 Python"
    echo "   请先安装 Python 3.8+：https://www.python.org/downloads/"
    exit 1
fi

# 检查/创建虚拟环境
if [ ! -d "venv" ]; then
    echo "📦 正在创建虚拟环境..."
    $PYTHON -m venv venv
fi

source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null

# 检查依赖是否已安装（只检查关键包 flask）
if ! $PYTHON -c "import flask" 2>/dev/null; then
    echo "📥 正在安装依赖（首次运行较慢）..."
    pip install --quiet flask flask-sqlalchemy openpyxl xlrd reportlab matplotlib pillow
fi

# 启动
echo ""
echo -e "${GREEN}✅ 启动完成！${NC}"
echo -e "${CYAN}🌐 请访问: http://localhost:5801${NC}"
echo -e "${CYAN}🔑 管理员: admin / admin123${NC}"
echo ""
echo "按 Ctrl+C 停止服务"
echo "========================================"
echo ""

$PYTHON app.py
