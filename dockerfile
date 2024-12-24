# 使用官方 Python 运行时作为父镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 将当前目录内容复制到容器的 /app 中
COPY . /app

# 安装项目依赖
RUN pip install --no-cache-dir -r requirements.txt

# 使 port 8080 可供此容器外的环境使用
EXPOSE 8080

# 定义环境变量
ENV SECRET_KEY your-secret-key
ENV DB_TYPE sqlite
ENV DB_PATH /app/serverless_registry.db
ENV REDIS_URL redis://redis:6379

# 运行 init.py 来初始化数据库（如果使用 SQLite）
RUN python init.py --type sqlite --path /app/serverless_registry.db

# 运行 server.py 当容器启动时
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "server:app"]