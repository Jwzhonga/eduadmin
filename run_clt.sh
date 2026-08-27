#!/bin/bash
# 班级管理系统启动脚本（M7：优先 .venv，回退 CLT Python）
cd "$(dirname "$0")"
if [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python app.py --port "${PORT:-5800}" "$@"
elif [ -x "/Library/Developer/CommandLineTools/usr/bin/python3" ]; then
    exec /Library/Developer/CommandLineTools/usr/bin/python3 app.py --port "${PORT:-5800}" "$@"
else
    echo "未找到可用 Python（.venv 或 CLT），请先安装依赖" >&2
    exit 1
fi
