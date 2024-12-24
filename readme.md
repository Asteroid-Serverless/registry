# Serverless Registry

这是一个用于管理serverless项目、组件和插件的注册中心。它提供了用户认证、包管理、版本控制等功能。

## 目录结构

```
serverless-registry/
│
├── init.py
├── server.py
├── test.py
├── Dockerfile
├── requirements.txt
└── README.md
```

## 初始化

1. 克隆仓库：

```bash
git clone https://github.com/your-repo/serverless-registry.git
cd serverless-registry
```

2. 创建虚拟环境：

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

3. 安装依赖：

```bash
pip install -r requirements.txt
```

4. 初始化数据库：

对于SQLite：

```bash
python init.py --type sqlite --path serverless_registry.db
```

对于MySQL：

```bash
python init.py --type mysql --host localhost --user your_username --password your_password --database serverless_registry
```

## 启动服务

```bash
python server.py
```

服务将在 `http://localhost:8080` 上运行。

## 单元测试

确保你已经创建了一个名为 `test.zip` 的测试文件在项目根目录下，然后运行：

```bash
python test.py
```

## 数据库结构

### 数据库表概览

| 表名 | 描述 |
|------|------|
| Users | 用户信息 |
| Packages | 包的基本信息 |
| Versions | 包的版本信息 |
| Providers | 云服务提供商信息 |
| PackageProviders | 包和提供商的关联 |
| Tags | 标签信息 |
| PackageTags | 包和标签的关联 |
| Services | 包提供的服务信息 |
| Commands | 包提供的命令信息 |
| Properties | 包的属性信息 |
| Tokens | 用户的认证令牌 |
| PackageMaintainers | 包的维护者信息 |
| Dependencies | 包的依赖关系 |
| Changelogs | 版本的更新日志 |
| PackageRatings | 包的评分信息 |
| AuditLogs | 审计日志 |

### 具体表结构

#### Users 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 用户ID |
| username | TEXT | UNIQUE NOT NULL | 用户名 |
| password_hash | TEXT | NOT NULL | 密码哈希 |
| email | TEXT | UNIQUE NOT NULL | 电子邮箱 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| last_login | TIMESTAMP | | 最后登录时间 |

#### Packages 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 包ID |
| name | VARCHAR(64) | NOT NULL UNIQUE | 包名 |
| type | TEXT | CHECK(type IN ('project', 'component', 'plugin')) NOT NULL | 包类型 |
| description | TEXT | | 包描述 |
| home | VARCHAR(255) | | 主页URL |
| create_time | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| update_time | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |
| downloads_count | INTEGER | DEFAULT 0 | 下载次数 |
| is_deprecated | BOOLEAN | DEFAULT 0 | 是否已废弃 |
| latest_version_id | INTEGER | FOREIGN KEY REFERENCES Versions(id) | 最新版本ID |

#### Versions 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 版本ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 包ID |
| version | VARCHAR(20) | NOT NULL | 版本号 |
| edition | VARCHAR(10) | NOT NULL | 版本类型 |
| description | TEXT | | 版本描述 |
| readme | TEXT | | README内容 |
| zipball_url | VARCHAR(255) | | ZIP文件URL |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| grayscale | FLOAT | DEFAULT 1 | 灰度发布比例 |
| status | TEXT | DEFAULT 'pending' | 版本状态 |
| downloads_count | INTEGER | DEFAULT 0 | 下载次数 |

#### Providers 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 提供商ID |
| name | VARCHAR(50) | NOT NULL UNIQUE | 提供商名称 |

#### PackageProviders 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 包ID |
| provider_id | INTEGER | FOREIGN KEY REFERENCES Providers(id) | 提供商ID |

#### Tags 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 标签ID |
| name | VARCHAR(50) | NOT NULL UNIQUE | 标签名称 |

#### PackageTags 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 包ID |
| tag_id | INTEGER | FOREIGN KEY REFERENCES Tags(id) | 标签ID |

#### Services 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 服务ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 包ID |
| service_name | VARCHAR(100) | NOT NULL | 服务名称 |
| permissions | TEXT | | 服务权限 |

#### Commands 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 命令ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 包ID |
| command_name | VARCHAR(50) | NOT NULL | 命令名称 |
| description | TEXT | | 命令描述 |

#### Properties 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 属性ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 包ID |
| property_name | VARCHAR(50) | NOT NULL | 属性名称 |
| property_value | TEXT | | 属性值 |

#### Tokens 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 令牌ID |
| user_id | INTEGER | NOT NULL FOREIGN KEY REFERENCES Users(id) | 用户ID |
| token | TEXT | NOT NULL | 令牌值 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| expired_at | TIMESTAMP | | 过期时间 |

#### PackageMaintainers 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| package_id | INTEGER | NOT NULL FOREIGN KEY REFERENCES Packages(id) | 包ID |
| user_id | INTEGER | NOT NULL FOREIGN KEY REFERENCES Users(id) | 用户ID |
| role | TEXT | NOT NULL | 维护者角色 |

#### Dependencies 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 依赖ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 包ID |
| dependency_package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 依赖包ID |
| version_constraint | TEXT | | 版本约束 |

#### Changelogs 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 更新日志ID |
| version_id | INTEGER | FOREIGN KEY REFERENCES Versions(id) | 版本ID |
| changelog | TEXT | | 更新日志内容 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

#### PackageRatings 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 评分ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | 包ID |
| user_id | INTEGER | FOREIGN KEY REFERENCES Users(id) | 用户ID |
| rating | INTEGER | CHECK(rating >= 1 AND rating <= 5) | 评分 |
| comment | TEXT | | 评论 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

#### AuditLogs 表

| 列名 | 类型 | 约束 | 描述 |
|------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 日志ID |
| user_id | INTEGER | FOREIGN KEY REFERENCES Users(id) | 用户ID |
| action | TEXT | | 操作类型 |
| details | TEXT | | 操作详情 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

## RESTful API

### API 概览

| 方法 | 路径 | 描述 | 认证要求 |
|------|------|------|----------|
| POST | /register | 注册新用户 | 无 |
| POST | /login | 用户登录 | 无 |
| POST | /logout | 用户登出 | 是 |
| POST | /refresh_token | 刷新认证令牌 | 是 |
| POST | /change_password | 修改密码 | 是 |
| POST | /releases | 创建/更新包 | 是 |
| POST | /upload/{upload_id} | 上传包文件 | 是 |
| GET | /{package_name}/releases | 获取所有版本 | 无 |
| GET | /{package_name}/releases/tags/{version} | 获取特定版本 | 无 |
| GET | /{package_name}/releases/latest | 获取最新版本 | 无 |
| GET | /search | 搜索包 | 无 |
| DELETE | /{package_name}/releases/tags/{version} | 删除特定版本 | 是 |
| GET | /{package_name}/zipball/{version} | 下载包 | 无 |
| POST | /{package_name}/maintainers | 添加维护者 | 是 |
| DELETE | /{package_name}/maintainers/{username} | 移除维护者 | 是 |

### API 详细信息

#### 注册新用户

- 方法: POST
- 路径: /register
- 描述: 注册新用户账户
- 请求体:
  ```json
  {
    "username": "string",
    "password": "string",
    "email": "string"
  }
  ```
- 响应:
  - 200 OK
    ```json
    {
      "message": "User registered successfully"
    }
    ```
  - 400 Bad Request
    ```json
    {
      "error": "Missing required fields"
    }
    ```
  - 409 Conflict
    ```json
    {
      "error": "Username or email already exists"
    }
    ```

#### 用户登录

- 方法: POST
- 路径: /login
- 描述: 用户登录并获取认证令牌
- 请求体:
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- 响应:
  - 200 OK
    ```json
    {
      "token": "string",
      "expires": "ISO8601 datetime string"
    }
    ```
  - 400 Bad Request
    ```json
    {
      "error": "Missing username or password"
    }
    ```
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid username or password"
    }
    ```

#### 用户登出

- 方法: POST
- 路径: /logout
- 描述: 用户登出，使当前令牌失效
- 请求头: 
  - Authorization: Bearer {token}
- 响应:
  - 200 OK
    ```json
    {
      "message": "Logged out successfully"
    }
    ```
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid or expired token"
    }
    ```

#### 刷新认证令牌

- 方法: POST
- 路径: /refresh_token
- 描述: 刷新用户的认证令牌
- 请求头: 
  - Authorization: Bearer {token}
- 响应:
  - 200 OK
    ```json
    {
      "token": "string",
      "expires": "ISO8601 datetime string"
    }
    ```
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid or expired token"
    }
    ```

#### 修改密码

- 方法: POST
- 路径: /change_password
- 描述: 修改用户密码
- 请求头: 
  - Authorization: Bearer {token}
- 请求体:
  ```json
  {
    "old_password": "string",
    "new_password": "string"
  }
  ```
- 响应:
  - 200 OK
    ```json
    {
      "message": "Password changed successfully"
    }
    ```
  - 400 Bad Request
    ```json
    {
      "error": "Missing old or new password"
    }
    ```
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid old password"
    }
    ```

#### 创建/更新包

- 方法: POST
- 路径: /releases
- 描述: 创建新包或更新现有包
- 请求头: 
  - Authorization: Bearer {token}
- 请求体:
  ```json
  {
    "name": "string",
    "version": "string",
    "description": "string",
    "type": "string",
    "provider": ["string"],
    "tags": ["string"],
    "service": {
      "service_name": "string",
      "permissions": "string"
    },
    "command": {
      "command_name": "string",
      "description": "string"
    },
    "properties": {
      "property_name": "string"
    }
  }
  ```
- 响应:
  - 201 Created
    ```json
    {
      "name": "string",
      "tag_name": "string",
      "created_at": "ISO8601 datetime string",
      "zipball_url": "string",
      "description": "string",
      "type": "string",
      "provider": ["string"],
      "tags": ["string"],
      "readme": "string",
      "home": "string"
    }
    ```
  - 400 Bad Request
    ```json
    {
      "error": "Invalid package data"
    }
    ```
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid or expired token"
    }
    ```
  - 403 Forbidden
    ```json
    {
      "error": "You don't have permission to modify this package"
    }
    ```

当然，我会继续完成API文档的其余部分。

#### 上传包文件

- 方法: POST
- 路径: /upload/{upload_id}
- 描述: 上传包文件
- 请求头: 
  - Authorization: Bearer {token}
- 请求体: 
  - 表单数据，包含一个名为 "package" 的文件字段
- 响应:
  - 200 OK
    ```json
    {
      "message": "Package uploaded successfully"
    }
    ```
  - 400 Bad Request
    ```json
    {
      "error": "No file uploaded"
    }
    ```
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid or expired token"
    }
    ```
  - 404 Not Found
    ```json
    {
      "error": "Invalid upload URL"
    }
    ```

#### 获取所有版本

- 方法: GET
- 路径: /{package_name}/releases
- 描述: 获取特定包的所有版本信息
- 响应:
  - 200 OK
    ```json
    [
      {
        "tag_name": "string",
        "created_at": "ISO8601 datetime string",
        "zipball_url": "string"
      }
    ]
    ```
  - 404 Not Found
    ```json
    {
      "error": "Package not found"
    }
    ```

#### 获取特定版本

- 方法: GET
- 路径: /{package_name}/releases/tags/{version}
- 描述: 获取特定包的特定版本信息
- 响应:
  - 200 OK
    ```json
    {
      "name": "string",
      "tag_name": "string",
      "created_at": "ISO8601 datetime string",
      "zipball_url": "string",
      "description": "string",
      "type": "string",
      "provider": ["string"],
      "tags": ["string"],
      "readme": "string",
      "home": "string"
    }
    ```
  - 404 Not Found
    ```json
    {
      "error": "Package or version not found"
    }
    ```

#### 获取最新版本

- 方法: GET
- 路径: /{package_name}/releases/latest
- 描述: 获取特定包的最新版本信息
- 响应:
  - 200 OK
    ```json
    {
      "name": "string",
      "tag_name": "string",
      "created_at": "ISO8601 datetime string",
      "zipball_url": "string",
      "description": "string",
      "type": "string",
      "provider": ["string"],
      "tags": ["string"],
      "readme": "string",
      "home": "string"
    }
    ```
  - 404 Not Found
    ```json
    {
      "error": "Package not found"
    }
    ```

#### 搜索包

- 方法: GET
- 路径: /search
- 描述: 搜索包
- 查询参数:
  - search: 搜索关键词
- 响应:
  - 200 OK
    ```json
    [
      {
        "name": "string",
        "tag_name": "string",
        "created_at": "ISO8601 datetime string",
        "zipball_url": "string"
      }
    ]
    ```
  - 400 Bad Request
    ```json
    {
      "error": "Search term is required"
    }
    ```

#### 删除特定版本

- 方法: DELETE
- 路径: /{package_name}/releases/tags/{version}
- 描述: 删除特定包的特定版本
- 请求头: 
  - Authorization: Bearer {token}
- 响应:
  - 204 No Content
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid or expired token"
    }
    ```
  - 403 Forbidden
    ```json
    {
      "error": "You don't have permission to delete this package version"
    }
    ```
  - 404 Not Found
    ```json
    {
      "error": "Package or version not found"
    }
    ```

#### 下载包

- 方法: GET
- 路径: /{package_name}/zipball/{version}
- 描述: 下载特定包的特定版本
- 响应:
  - 200 OK
    - Content-Type: application/zip
    - Body: 二进制文件内容
  - 404 Not Found
    ```json
    {
      "error": "Package or version not found"
    }
    ```

#### 添加维护者

- 方法: POST
- 路径: /{package_name}/maintainers
- 描述: 为特定包添加维护者
- 请求头: 
  - Authorization: Bearer {token}
- 请求体:
  ```json
  {
    "username": "string",
    "role": "string"
  }
  ```
- 响应:
  - 200 OK
    ```json
    {
      "message": "Added {username} as {role} to {package_name}"
    }
    ```
  - 400 Bad Request
    ```json
    {
      "error": "Missing new maintainer username"
    }
    ```
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid or expired token"
    }
    ```
  - 403 Forbidden
    ```json
    {
      "error": "You don't have permission to add maintainers to this package"
    }
    ```
  - 404 Not Found
    ```json
    {
      "error": "User not found"
    }
    ```

#### 移除维护者

- 方法: DELETE
- 路径: /{package_name}/maintainers/{username}
- 描述: 从特定包中移除维护者
- 请求头: 
  - Authorization: Bearer {token}
- 响应:
  - 200 OK
    ```json
    {
      "message": "Removed {username} from maintainers of {package_name}"
    }
    ```
  - 401 Unauthorized
    ```json
    {
      "error": "Invalid or expired token"
    }
    ```
  - 403 Forbidden
    ```json
    {
      "error": "You don't have permission to remove maintainers from this package"
    }
    ```
  - 404 Not Found
    ```json
    {
      "error": "User is not a maintainer of this package or is the owner"
    }
    ```

当然，我会重新编写文档中的签名认证部分，以包含新的防重放攻击机制。以下是更新后的签名认证部分：

### 签名认证

为了提高安全性并防止重放攻击，我们实现了一个增强的签名认证机制。每个需要认证的API请求都应该包含以下头部：

- `X-Api-Key`: API密钥（由服务器分配给客户端）
- `X-Timestamp`: 当前时间戳（Unix时间戳）
- `X-Nonce`: 随机生成的字符串，用于确保请求的唯一性
- `X-Signature`: 请求签名

#### 签名生成方法

1. 将请求方法、请求路径、时间戳、nonce和请求体（如果有）连接成一个字符串
2. 使用API密钥对这个字符串进行HMAC-SHA256加密
3. 将加密结果转换为Base64编码

#### 服务器验证步骤

1. 检查时间戳是否在允许的时间范围内（10秒内）
2. 验证nonce在过去10秒内是否未被使用
3. 使用相同的方法生成签名
4. 比较生成的签名与请求中的签名是否一致

#### Python实现示例

```python
import hmac
import hashlib
import base64
import time
import uuid
from collections import deque

# 用于存储最近使用的 nonce
USED_NONCES = deque(maxlen=1000)  # 限制存储的 nonce 数量，避免无限增长

def generate_signature(method, path, timestamp, nonce, body, api_key):
    message = f"{method}{path}{timestamp}{nonce}{body}"
    signature = hmac.new(api_key.encode(), message.encode(), hashlib.sha256)
    return base64.b64encode(signature.digest()).decode()

def verify_signature(request, api_key):
    timestamp = request.headers.get('X-Timestamp')
    nonce = request.headers.get('X-Nonce')
    provided_signature = request.headers.get('X-Signature')
    
    if not timestamp or not nonce or not provided_signature:
        return False
    
    current_time = int(time.time())
    
    # 检查时间戳是否在10秒内
    if abs(int(timestamp) - current_time) > 10:
        return False
    
    # 检查 nonce 是否已被使用
    if nonce in USED_NONCES:
        return False
    
    calculated_signature = generate_signature(
        request.method,
        request.path,
        timestamp,
        nonce,
        request.body.read().decode() if request.body else '',
        api_key
    )
    
    if hmac.compare_digest(provided_signature, calculated_signature):
        # 如果签名验证通过，将 nonce 添加到已使用列表
        USED_NONCES.append(nonce)
        return True
    
    return False

# 客户端使用示例
def client_request(method, path, body, api_key):
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())  # 生成随机的 nonce
    
    signature = generate_signature(method, path, timestamp, nonce, body, api_key)
    
    headers = {
        'X-Api-Key': api_key,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': signature
    }
    
    # 这里应该是实际的 HTTP 请求
    print(f"Sending request with headers: {headers}")
```

#### 注意事项

1. 时间同步：确保客户端和服务器的时钟保持同步，否则可能导致请求被错误地拒绝。

2. Nonce 存储：在高并发环境下，考虑使用分布式缓存（如Redis）来存储最近使用的nonce，以确保系统的可扩展性。

3. 定期清理：定期清理过期的nonce记录，以防止内存无限增长。

4. 负载均衡：如果使用了负载均衡，确保nonce的验证在所有服务器间保持一致。

5. HTTPS：虽然签名机制提供了一定的安全性，但仍然强烈建议通过HTTPS传输所有API请求，以防止中间人攻击。

6. API密钥保护：确保API密钥得到妥善保管，不要在客户端代码中硬编码或暴露在公共场合。

通过实施这种增强的签名认证机制，我们可以有效地防止重放攻击，提高API调用的安全性和完整性。每个请求都具有唯一性（由nonce保证）和时效性（由时间戳保证），大大增加了伪造或重放有效请求的难度。

## 注意事项

- 所有需要认证的API都需要在请求头中包含 `Authorization` 字段，其值为登录时获得的token。
- 该项目包含速率限制功能，以防止API滥用。
- 请确保在生产环境中使用更安全的配置，如使用HTTPS，更改默认的密钥等。