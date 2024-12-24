from bottle import Bottle, run, request, response, abort, static_file
import os
import json
import time
import uuid
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
import redis
from rq import Queue
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
import hashlib

app = Bottle()

# 配置
SECRET_KEY = os.environ.get('SECRET_KEY', "your-secret-key")
DB_TYPE = os.environ.get('DB_TYPE', 'sqlite')
if DB_TYPE == 'sqlite':
    DB_PATH = os.environ.get('DB_PATH', 'serverless_registry.db')
    DATABASE_URL = f"sqlite:///{DB_PATH}"
elif DB_TYPE == 'mysql':
    DB_CONFIG = {
        'host': os.environ.get('DB_HOST', 'localhost'),
        'user': os.environ.get('DB_USER', 'root'),
        'password': os.environ.get('DB_PASSWORD', ''),
        'database': os.environ.get('DB_NAME', 'serverless_registry')
    }
    DATABASE_URL = f"mysql+mysqlconnector://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}/{DB_CONFIG['database']}"
else:
    raise ValueError("Unsupported database type")

PACKAGE_DIR = 'packages'
if not os.path.exists(PACKAGE_DIR):
    os.makedirs(PACKAGE_DIR)

REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
TIME_TOLERANCE = 10  # 允许的最大时间差（秒）
NONCE_EXPIRATION = 10  # nonce的有效期（秒）

# Redis 连接
redis_client = redis.from_url(REDIS_URL)
task_queue = Queue(connection=redis_client)

# 日志配置
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SQLAlchemy 设置
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

# 认证装饰器
def authenticate(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            abort(401, "Missing authentication header")

        try:
            # 解析认证头
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() != 'sign':
                abort(401, "Invalid authentication type")

            # 解析认证字符串
            auth_parts = dict(part.split('=') for part in auth_string.split(','))
            access_key = auth_parts.get('access_key')
            signature = auth_parts.get('signature')
            timestamp = auth_parts.get('timestamp')
            nonce = auth_parts.get('nonce')

            if not all([access_key, signature, timestamp, nonce]):
                abort(401, "Missing authentication parameters")

            # 验证时间戳
            current_time = int(time.time())
            if abs(current_time - int(timestamp)) > TIME_TOLERANCE:
                abort(401, "Timestamp out of tolerance")

            # 验证nonce
            nonce_key = f"nonce:{access_key}:{nonce}"
            if redis_client.get(nonce_key):
                abort(401, "Nonce already used")
            redis_client.setex(nonce_key, NONCE_EXPIRATION, "1")

            # 验证签名
            session = Session()
            result = session.execute(text("""
                SELECT user_id, secret_key 
                FROM Tokens 
                WHERE access_key = :access_key AND expired_at > :now
            """), {
                "access_key": access_key,
                "now": datetime.utcnow()
            })
            user = result.fetchone()
            session.close()

            if not user:
                abort(401, "Invalid or expired access key")

            user_id, secret_key = user
            string_to_sign = f"{access_key}{timestamp}{nonce}"
            expected_signature = hashlib.sha256(f"{string_to_sign}{secret_key}".encode()).hexdigest()

            if signature != expected_signature:
                abort(401, "Invalid signature")

            return f(user_id, *args, **kwargs)
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            abort(500, str(e))

    return decorated

# 速率限制装饰器
def rate_limit(limit=100, per=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            client_ip = request.remote_addr
            key = f"{client_ip}:{request.path}"
            current = redis_client.get(key)
            
            if current is None:
                redis_client.setex(key, per, 1)
            elif int(current) >= limit:
                abort(429, "Rate limit exceeded")
            else:
                redis_client.incr(key)
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# 路由
@app.post('/register')
@rate_limit(10, 3600)  # 每小时限制10次注册
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        abort(400, "Missing required fields")

    try:
        session = Session()
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        session.execute(text(
            "INSERT INTO Users (username, password_hash, email) VALUES (:username, :password, :email)"
        ), {"username": username, "password": hashed, "email": email})
        session.commit()
        session.close()
        return {"message": "User registered successfully"}
    except SQLAlchemyError as e:
        logger.error(f"Registration error: {str(e)}")
        abort(409, "Username or email already exists")

@app.post('/login')
@rate_limit(5, 60)  # 每分钟限制5次登录尝试
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        abort(400, "Missing username or password")

    try:
        session = Session()
        result = session.execute(text(
            "SELECT id, password_hash FROM Users WHERE username = :username"
        ), {"username": username})
        user = result.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            access_key = str(uuid.uuid4())
            secret_key = str(uuid.uuid4())
            expiration = datetime.utcnow() + timedelta(days=30)
            
            session.execute(text("""
                INSERT INTO Tokens (user_id, access_key, secret_key, expired_at) 
                VALUES (:user_id, :access_key, :secret_key, :expired_at)
            """), {
                "user_id": user[0], 
                "access_key": access_key, 
                "secret_key": secret_key, 
                "expired_at": expiration
            })
            session.commit()
            session.close()

            return {
                "access_key": access_key, 
                "secret_key": secret_key, 
                "expires": expiration.isoformat()
            }
        else:
            abort(401, "Invalid username or password")
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        abort(500, str(e))

@app.post('/logout')
@authenticate
def logout(user_id):
    access_key = request.headers.get('Authorization').split(' ', 1)[1].split(',')[0].split('=')[1]
    try:
        session = Session()
        session.execute(text("DELETE FROM Tokens WHERE access_key = :access_key"), {"access_key": access_key})
        session.commit()
        session.close()
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        abort(500, str(e))

@app.post('/refresh_token')
@authenticate
def refresh_token(user_id):
    old_access_key = request.headers.get('Authorization').split(' ', 1)[1].split(',')[0].split('=')[1]
    try:
        session = Session()
        
        # 生成新的 access_key 和 secret_key
        new_access_key = str(uuid.uuid4())
        new_secret_key = str(uuid.uuid4())
        expiration = datetime.utcnow() + timedelta(days=30)
        
        # 更新数据库中的记录
        session.execute(text("""
            UPDATE Tokens 
            SET access_key = :new_access_key, 
                secret_key = :new_secret_key, 
                expired_at = :expiration
            WHERE user_id = :user_id AND access_key = :old_access_key
        """), {
            "new_access_key": new_access_key,
            "new_secret_key": new_secret_key,
            "expiration": expiration,
            "user_id": user_id,
            "old_access_key": old_access_key
        })
        
        if session.execute(text("SELECT ROW_COUNT()")).fetchone()[0] == 0:
            session.close()
            abort(404, "Token not found or user mismatch")
        
        session.commit()
        session.close()
        
        return {
            "access_key": new_access_key,
            "secret_key": new_secret_key,
            "expires": expiration.isoformat()
        }
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        abort(500, str(e))

@app.post('/change_password')
@authenticate
def change_password(user_id):
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        abort(400, "Missing old or new password")

    try:
        session = Session()
        result = session.execute(text(
            "SELECT password_hash FROM Users WHERE id = :user_id"
        ), {"user_id": user_id})
        user = result.fetchone()

        if not user or not bcrypt.checkpw(old_password.encode('utf-8'), user[0].encode('utf-8')):
            session.close()
            abort(401, "Invalid old password")

        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        session.execute(text(
            "UPDATE Users SET password_hash = :new_hash WHERE id = :user_id"
        ), {"new_hash": new_hash, "user_id": user_id})
        session.commit()
        session.close()

        return {"message": "Password changed successfully"}
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        abort(500, str(e))

@app.post('/releases')
@authenticate
@rate_limit(20, 3600)  # 每小时限制20次发布
def create_package(user_id):
    data = request.json
    if not data or 'name' not in data or 'version' not in data:
        abort(422, "Invalid package data")

    try:
        session = Session()
        # 检查包是否存在
        result = session.execute(text(
            "SELECT id FROM Packages WHERE name = :name"
        ), {"name": data['name']})
        package = result.fetchone()
        
        if package:
            package_id = package[0]
            # 检查用户是否有权限修改这个包
            result = session.execute(text('''
            SELECT role FROM PackageMaintainers 
            WHERE package_id = :package_id AND user_id = :user_id
            '''), {"package_id": package_id, "user_id": user_id})
            maintainer = result.fetchone()
            if not maintainer:
                abort(403, "You don't have permission to modify this package")
        else:
            # 创建新包
            result = session.execute(text('''
            INSERT INTO Packages (name, type, description, home)
            VALUES (:name, :type, :description, :home)
            '''), {
                "name": data['name'],
                "type": data.get('type', 'project'),
                "description": data.get('description', ''),
                "home": data.get('home', '')
            })
            package_id = result.lastrowid
            # 将创建者添加为包的所有者
            session.execute(text('''
            INSERT INTO PackageMaintainers (package_id, user_id, role)
            VALUES (:package_id, :user_id, 'owner')
            '''), {"package_id": package_id, "user_id": user_id})

        # 生成唯一的上传 URL
        upload_id = str(uuid.uuid4())
        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
        upload_url = f"{base_url}/upload/{upload_id}"

        # 创建新版本
        session.execute(text('''
        INSERT INTO Versions (package_id, version, edition, description, readme, zipball_url, grayscale, status)
        VALUES (:package_id, :version, :edition, :description, :readme, :zipball_url, :grayscale, 'pending')
        '''), {
            "package_id": package_id,
            "version": data['version'],
            "edition": data.get('edition', '3.0.0'),
            "description": data.get('description', ''),
            "readme": data.get('readme', ''),
            "zipball_url": upload_url,
            "grayscale": data.get('grayscale', 1)
        })


        # 处理提供商
        for provider in data.get('provider', []):
            session.execute(text("INSERT IGNORE INTO Providers (name) VALUES (:name)"), {"name": provider})
            result = session.execute(text("SELECT id FROM Providers WHERE name = :name"), {"name": provider})
            provider_id = result.fetchone()[0]
            session.execute(text(
                "INSERT IGNORE INTO PackageProviders (package_id, provider_id) VALUES (:package_id, :provider_id)"
            ), {"package_id": package_id, "provider_id": provider_id})

        # 处理标签
        for tag in data.get('tags', []):
            session.execute(text("INSERT IGNORE INTO Tags (name) VALUES (:name)"), {"name": tag})
            result = session.execute(text("SELECT id FROM Tags WHERE name = :name"), {"name": tag})
            tag_id = result.fetchone()[            0]
            session.execute(text(
                "INSERT IGNORE INTO PackageTags (package_id, tag_id) VALUES (:package_id, :tag_id)"
            ), {"package_id": package_id, "tag_id": tag_id})

        # 处理服务
        for service_name, permissions in data.get('service', {}).items():
            session.execute(text('''
            INSERT INTO Services (package_id, service_name, permissions)
            VALUES (:package_id, :service_name, :permissions)
            '''), {"package_id": package_id, "service_name": service_name, "permissions": json.dumps(permissions)})

        # 处理命令（仅适用于组件）
        if data.get('type') == 'component':
            for command_name, description in data.get('command', {}).items():
                session.execute(text('''
                INSERT INTO Commands (package_id, command_name, description)
                VALUES (:package_id, :command_name, :description)
                '''), {"package_id": package_id, "command_name": command_name, "description": description})

        # 处理属性
        for property_name, property_value in data.get('properties', {}).items():
            session.execute(text('''
            INSERT INTO Properties (package_id, property_name, property_value)
            VALUES (:package_id, :property_name, :property_value)
            '''), {"package_id": package_id, "property_name": property_name, "property_value": json.dumps(property_value)})

        session.commit()

        # 获取创建的包信息
        result = session.execute(text('''
        SELECT p.name, v.version, v.created_at, v.zipball_url, v.description, p.type,
               GROUP_CONCAT(DISTINCT pr.name) as providers,
               GROUP_CONCAT(DISTINCT t.name) as tags,
               v.readme, p.home
        FROM Packages p
        JOIN Versions v ON p.id = v.package_id
        LEFT JOIN PackageProviders pp ON p.id = pp.package_id
        LEFT JOIN Providers pr ON pp.provider_id = pr.id
        LEFT JOIN PackageTags pt ON p.id = pt.package_id
        LEFT JOIN Tags t ON pt.tag_id = t.id
        WHERE p.name = :name AND v.version = :version
        GROUP BY p.id, v.id
        '''), {"name": data['name'], "version": data['version']})
        result = result.fetchone()

        package_data = {
            "name": result[0],
            "tag_name": result[1],
            "created_at": result[2].isoformat(),
            "zipball_url": result[3],
            "description": result[4],
            "type": result[5],
            "provider": result[6].split(',') if result[6] else [],
            "tags": result[7].split(',') if result[7] else [],
            "readme": result[8],
            "home": result[9]
        }

        session.close()
        response.status = 201
        return json.dumps(package_data)

    except Exception as e:
        logger.error(f"Package creation error: {str(e)}")
        abort(500, str(e))

@app.post('/upload/<upload_id>')
@authenticate
def upload_package(user_id, upload_id):
    upload = request.files.get('package')
    if not upload:
        abort(400, "No file uploaded")

    if not upload.filename.endswith('.zip'):
        abort(400, "File must be a zip archive")

    try:
        session = Session()
        # 查找对应的版本记录
        result = session.execute(text('''
        SELECT p.name, v.version
        FROM Versions v
        JOIN Packages p ON v.package_id = p.id
        WHERE v.zipball_url LIKE :upload_url
        '''), {"upload_url": f'%{upload_id}%'})
        result = result.fetchone()

        if not result:
            abort(404, "Invalid upload URL")

        package_name, version = result[0], result[1]

        # 保存文件
        file_path = os.path.join(PACKAGE_DIR, f"{package_name}-{version}.zip")
        upload.save(file_path)

        # 构建基础 URL
        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"

        # 更新版本状态
        session.execute(text('''
        UPDATE Versions
        SET status = 'active', zipball_url = :zipball_url
        WHERE package_id = (SELECT id FROM Packages WHERE name = :package_name)
        AND version = :version
        '''), {
            "zipball_url": f"{base_url}/{package_name}/zipball/{version}",
            "package_name": package_name,
            "version": version
        })

        session.commit()
        session.close()

        response.status = 200
        return json.dumps({"message": "Package uploaded successfully"})

    except Exception as e:
        logger.error(f"Package upload error: {str(e)}")
        abort(500, str(e))

@app.get('/<package_name>/releases')
@rate_limit(100, 60)  # 每分钟限制100次请求
def get_all_versions(package_name):
    try:
        session = Session()
        result = session.execute(text('''
        SELECT v.version, v.created_at, v.zipball_url
        FROM Packages p
        JOIN Versions v ON p.id = v.package_id
        WHERE p.name = :package_name
        '''), {"package_name": package_name})
        versions = result.fetchall()
        session.close()

        if not versions:
            abort(404, "Package not found")

        result = [
            {
                "tag_name": version[0],
                "created_at": version[1].isoformat(),
                "zipball_url": version[2]
            }
            for version in versions
        ]
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error fetching versions: {str(e)}")
        abort(500, str(e))

@app.get('/<package_name>/releases/tags/<version>')
@rate_limit(100, 60)  # 每分钟限制100次请求
def get_specific_version(package_name, version):
    try:
        session = Session()
        result = session.execute(text('''
        SELECT p.name, v.version, v.created_at, v.zipball_url, v.description, p.type,
               GROUP_CONCAT(DISTINCT pr.name) as providers,
               GROUP_CONCAT(DISTINCT t.name) as tags,
               v.readme, p.home
        FROM Packages p
        JOIN Versions v ON p.id = v.package_id
        LEFT JOIN PackageProviders pp ON p.id = pp.package_id
        LEFT JOIN Providers pr ON pp.provider_id = pr.id
        LEFT JOIN PackageTags pt ON p.id = pt.package_id
        LEFT JOIN Tags t ON pt.tag_id = t.id
        WHERE p.name = :package_name AND v.version = :version
        GROUP BY p.id, v.id
        '''), {"package_name": package_name, "version": version})
        result = result.fetchone()
        session.close()

        if not result:
            abort(404, "Package or version not found")

        package_data = {
            "name": result[0],
            "tag_name": result[1],
            "created_at": result[2].isoformat(),
            "zipball_url": result[3],
            "description": result[4],
            "type": result[5],
            "provider": result[6].split(',') if result[6] else [],
            "tags": result[7].split(',') if result[7] else [],
            "readme": result[8],
            "home": result[9]
        }

        return json.dumps(package_data)
    except Exception as e:
        logger.error(f"Error fetching specific version: {str(e)}")
        abort(500, str(e))

@app.get('/<package_name>/releases/latest')
@rate_limit(100, 60)  # 每分钟限制100次请求
def get_latest_version(package_name):
    try:
        session = Session()
        result = session.execute(text('''
        SELECT p.name, v.version, v.created_at, v.zipball_url, v.description, p.type,
               GROUP_CONCAT(DISTINCT pr.name) as providers,
               GROUP_CONCAT(DISTINCT t.name) as tags,
               v.readme, p.home
        FROM Packages p
        JOIN Versions v ON p.id = v.package_id
        LEFT JOIN PackageProviders pp ON p.id = pp.package_id
        LEFT JOIN Providers pr ON pp.provider_id = pr.id
        LEFT JOIN PackageTags pt ON p.id = pt.package_id
        LEFT JOIN Tags t ON pt.tag_id = t.id
        WHERE p.name = :package_name
        GROUP BY p.id, v.id
        ORDER BY v.created_at DESC
        LIMIT 1
        '''), {"package_name": package_name})
        result = result.fetchone()
        session.close()

        if not result:
            abort(404, "Package not found")

        package_data = {
            "name": result[0],
            "tag_name": result[1],
            "created_at": result[2].isoformat(),
            "zipball_url": result[3],
            "description": result[4],
            "type": result[5],
            "provider": result[6].split(',') if result[6] else [],
            "tags": result[7].split(',') if result[7] else [],
            "readme": result[8],
            "home": result[9]
        }

        return json.dumps(package_data)
    except Exception as e:
        logger.error(f"Error fetching latest version: {str(e)}")
        abort(500, str(e))

@app.get('/search')
@rate_limit(100, 60)  # 每分钟限制100次请求
def search_packages():
    search_term = request.query.search
    if not search_term:
        abort(400, "Search term is required")

    try:
        session = Session()
        result = session.execute(text('''
        SELECT DISTINCT p.name, v.version, v.created_at, v.zipball_url
        FROM Packages p
        JOIN Versions v ON p.id = v.package_id
        WHERE p.name LIKE :search_term OR p.description LIKE :search_term
        ORDER BY v.created_at DESC
        '''), {"search_term": f'%{search_term}%'})
        results = result.fetchall()
        session.close()

        return json.dumps([
            {
                "name": result[0],
                "tag_name": result[1],
                "created_at": result[2].isoformat(),
                "zipball_url": result[3]
            }
            for result in results
        ])
    except Exception as e:
        logger.error(f"Error searching packages: {str(e)}")
        abort(500, str(e))

@app.delete('/<package_name>/releases/tags/<version>')
@authenticate
def delete_version(user_id, package_name, version):
    try:
        session = Session()
        # 检查用户是否有权限删除该包
        result = session.execute(text('''
        SELECT pm.role 
        FROM Packages p
        JOIN PackageMaintainers pm ON p.id = pm.package_id
        WHERE p.name = :package_name AND pm.user_id = :user_id
        '''), {"package_name": package_name, "user_id": user_id})
        result = result.fetchone()

        if not result or result[0] not in ['owner', 'maintainer']:
            session.close()
            abort(403, "You don't have permission to delete this package version")

        session.execute(text('''
        DELETE FROM Versions
        WHERE version = :version AND package_id = (SELECT id FROM Packages WHERE name = :package_name)
        '''), {"version": version, "package_name": package_name})
        
        if session.execute(text("SELECT ROW_COUNT()")).fetchone()[0] == 0:
            session.close()
            abort(404, "Package or version not found")
        
        session.commit()
        session.close()
        response.status = 204
        return
    except Exception as e:
        logger.error(f"Error deleting version: {str(e)}")
        abort(500, str(e))

@app.get('/<package_name>/zipball/<version>')
@rate_limit(50, 60)  # 每分钟限制50次下载请求
def download_package(package_name, version):
    try:
        session = Session()
        result = session.execute(text('''
        SELECT v.status
        FROM Packages p
        JOIN Versions v ON p.id = v.package_id
        WHERE p.name = :package_name AND v.version = :version
        '''), {"package_name": package_name, "version": version})
        result = result.fetchone()
        session.close()

        if not result:
            abort(404, "Package or version not found")

        if result[0] != 'active':
            abort(404, "Package is not available for download")

        file_path = os.path.join(PACKAGE_DIR, f"{package_name}-{version}.zip")
        if not os.path.exists(file_path):
            abort(404, "Package file not found")

        return static_file(f"{package_name}-{version}.zip", root=PACKAGE_DIR, download=True)
    except Exception as e:
        logger.error(f"Error downloading package: {str(e)}")
        abort(500, str(e))

@app.post('/<package_name>/maintainers')
@authenticate
def add_maintainer(user_id, package_name):
    data = request.json
    new_maintainer_username = data.get('username')
    role = data.get('role', 'maintainer')

    if not new_maintainer_username:
        abort(400, "Missing new maintainer username")

    try:
        session = Session()
        # 检查当前用户是否是包的所有者
        result = session.execute(text('''
        SELECT p.id, pm.role 
        FROM Packages p
        JOIN PackageMaintainers pm ON p.id = pm.package_id
        WHERE p.name = :package_name AND pm.user_id = :user_id
        '''), {"package_name": package_name, "user_id": user_id})
        result = result.fetchone()

        if not result or result[1] != 'owner':
            session.close()
            abort(403, "You don't have permission to add maintainers to this package")

        package_id = result[0]

        # 获取新维护者的用户 ID
        result = session.execute(text("SELECT id FROM Users WHERE username = :username"), 
                                 {"username": new_maintainer_username})
        new_maintainer = result.fetchone()

        if not new_maintainer:
            session.close()
            abort(404, "User not found")

        new_maintainer_id = new_maintainer[0]

        # 添加新维护者
        session.execute(text('''
        INSERT INTO PackageMaintainers (package_id, user_id, role)
        VALUES (:package_id, :user_id, :role)
        ON DUPLICATE KEY UPDATE role = :role
        '''), {"package_id": package_id, "user_id": new_maintainer_id, "role": role})

        session.commit()
        session.close()
        return {"message": f"Added {new_maintainer_username} as {role} to {package_name}"}
    except Exception as e:
        logger.error(f"Error adding maintainer: {str(e)}")
        abort(500, str(e))

@app.delete('/<package_name>/maintainers/<username>')
@authenticate
def remove_maintainer(user_id, package_name, username):
    try:
        session = Session()
        # 检查当前用户是否是包的所有者
        result = session.execute(text('''
        SELECT p.id, pm.role 
        FROM Packages p
        JOIN PackageMaintainers pm ON p.id = pm.package_id
        WHERE p.name = :package_name AND pm.user_id = :user_id
        '''), {"package_name": package_name, "user_id": user_id})
        result = result.fetchone()

        if not result or result[1] != 'owner':
            session.close()
            abort(403, "You don't have permission to remove maintainers from this package")

        package_id = result[0]

        # 获取要移除的维护者的用户 ID
        result = session.execute(text("SELECT id FROM Users WHERE username = :username"), 
                                 {"username": username})
        maintainer = result.fetchone()

        if not maintainer:
            session.close()
            abort(404, "User not found")

        maintainer_id = maintainer[0]

        # 移除维护者
        session.execute(text('''
        DELETE FROM PackageMaintainers 
        WHERE package_id = :package_id AND user_id = :user_id AND role != 'owner'
        '''), {"package_id": package_id, "user_id": maintainer_id})

        if session.execute(text("SELECT ROW_COUNT()")).fetchone()[0] == 0:
            session.close()
            abort(404, "User is not a maintainer of this package or is the owner")

        session.commit()
        session.close()
        return {"message": f"Removed {username} from maintainers of {package_name}"}
    except Exception as e:
        logger.error(f"Error removing maintainer: {str(e)}")
        abort(500, str(e))

if __name__ == '__main__':
    run(app, host='0.0.0.0', port=8080, server='gunicorn', workers=4)
