# Dockerfile（放在含 app.py/requirements.txt 的那个目录）
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝代码
COPY . .

# Cloud Run 会注入 PORT，因此一定要监听 ${PORT}
CMD ["bash","-lc","python - <<'PY'\nimport traceback, importlib, sys\ntry:\n m = importlib.import_module('cti_platform.app'); print('import OK:', hasattr(m,'app'))\nexcept Exception:\n traceback.print_exc(); sys.exit(1)\nPY\n && exec gunicorn -c /dev/null cti_platform.app:app --bind 0.0.0.0:${PORT} --workers 1 --timeout 120 --log-level debug --capture-output"]
