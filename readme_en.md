# Serverless Registry

This is a registry for managing serverless projects, components, and plugins. It provides features such as user authentication, package management, and version control.

English | [中文](readme.md)

## Directory Structure

```
registry/
│
├── init.py
├── server.py
├── test.py
├── Dockerfile
├── requirements.txt
└── README.md
```

## Initialization

1. Clone the repository:

```bash
git clone https://github.com/Asteroid-Serverless/registry.git
cd registry
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Initialize the database:

For SQLite:

```bash
python init.py --type sqlite --path serverless_registry.db
```

For MySQL:

```bash
python init.py --type mysql --host localhost --user your_username --password your_password --database serverless_registry
```

## Start the Service

```bash
python server.py
```

The service will run on `http://localhost:8080`.

## Unit Tests

Ensure you have created a test file named `test.zip` in the project root directory, then run:

```bash
python test.py
```

## Database Structure

### Database Table Overview

| Table Name | Description |
|------------|-------------|
| Users | User information |
| Packages | Basic package information |
| Versions | Package version information |
| Providers | Cloud service provider information |
| PackageProviders | Association between packages and providers |
| Tags | Tag information |
| PackageTags | Association between packages and tags |
| Services | Service information provided by packages |
| Commands | Command information provided by packages |
| Properties | Package property information |
| Tokens | User authentication tokens |
| PackageMaintainers | Package maintainer information |
| Dependencies | Package dependency relationships |
| Changelogs | Version update logs |
| PackageRatings | Package rating information |
| AuditLogs | Audit logs |

### Specific Table Structures

#### Users Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | User ID |
| username | TEXT | UNIQUE NOT NULL | Username |
| password_hash | TEXT | NOT NULL | Password hash |
| email | TEXT | UNIQUE NOT NULL | Email address |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Creation time |
| last_login | TIMESTAMP | | Last login time |

#### Packages Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Package ID |
| name | VARCHAR(64) | NOT NULL UNIQUE | Package name |
| type | TEXT | CHECK(type IN ('project', 'component', 'plugin')) NOT NULL | Package type |
| description | TEXT | | Package description |
| home | VARCHAR(255) | | Homepage URL |
| create_time | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Creation time |
| update_time | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Update time |
| downloads_count | INTEGER | DEFAULT 0 | Download count |
| is_deprecated | BOOLEAN | DEFAULT 0 | Whether deprecated |
| latest_version_id | INTEGER | FOREIGN KEY REFERENCES Versions(id) | Latest version ID |

#### Versions Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Version ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Package ID |
| version | VARCHAR(20) | NOT NULL | Version number |
| edition | VARCHAR(10) | NOT NULL | Version type |
| description | TEXT | | Version description |
| readme | TEXT | | README content |
| zipball_url | VARCHAR(255) | | ZIP file URL |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Creation time |
| grayscale | FLOAT | DEFAULT 1 | Grayscale release ratio |
| status | TEXT | DEFAULT 'pending' | Version status |
| downloads_count | INTEGER | DEFAULT 0 | Download count |

#### Providers Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Provider ID |
| name | VARCHAR(50) | NOT NULL UNIQUE | Provider name |

#### PackageProviders Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Package ID |
| provider_id | INTEGER | FOREIGN KEY REFERENCES Providers(id) | Provider ID |

#### Tags Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Tag ID |
| name | VARCHAR(50) | NOT NULL UNIQUE | Tag name |

#### PackageTags Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Package ID |
| tag_id | INTEGER | FOREIGN KEY REFERENCES Tags(id) | Tag ID |

#### Services Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Service ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Package ID |
| service_name | VARCHAR(100) | NOT NULL | Service name |
| permissions | TEXT | | Service permissions |

#### Commands Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Command ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Package ID |
| command_name | VARCHAR(50) | NOT NULL | Command name |
| description | TEXT | | Command description |

#### Properties Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Property ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Package ID |
| property_name | VARCHAR(50) | NOT NULL | Property name |
| property_value | TEXT | | Property value |

#### Tokens Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Token ID |
| user_id | INTEGER | NOT NULL FOREIGN KEY REFERENCES Users(id) | User ID |
| token | TEXT | NOT NULL | Token value |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Creation time |
| expired_at | TIMESTAMP | | Expiration time |

#### PackageMaintainers Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| package_id | INTEGER | NOT NULL FOREIGN KEY REFERENCES Packages(id) | Package ID |
| user_id | INTEGER | NOT NULL FOREIGN KEY REFERENCES Users(id) | User ID |
| role | TEXT | NOT NULL | Maintainer role |

#### Dependencies Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Dependency ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Package ID |
| dependency_package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Dependency package ID |
| version_constraint | TEXT | | Version constraint |

#### Changelogs Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Changelog ID |
| version_id | INTEGER | FOREIGN KEY REFERENCES Versions(id) | Version ID |
| changelog | TEXT | | Changelog content |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Creation time |

#### PackageRatings Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Rating ID |
| package_id | INTEGER | FOREIGN KEY REFERENCES Packages(id) | Package ID |
| user_id | INTEGER | FOREIGN KEY REFERENCES Users(id) | User ID |
| rating | INTEGER | CHECK(rating >= 1 AND rating <= 5) | Rating |
| comment | TEXT | | Comment |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Creation time |

#### AuditLogs Table

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | Log ID |
| user_id | INTEGER | FOREIGN KEY REFERENCES Users(id) | User ID |
| action | TEXT | | Action type |
| details | TEXT | | Action details |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Creation time |

## RESTful API

### API Overview

| Method | Path | Description | Authentication Required |
|--------|------|-------------|--------------------------|
| POST | /register | Register new user | No |
| POST | /login | User login | No |
| POST | /logout | User logout | Yes |
| POST | /refresh_token | Refresh authentication token | Yes |
| POST | /change_password | Change password | Yes |
| POST | /releases | Create/update package | Yes |
| POST | /upload/{upload_id} | Upload package file | Yes |
| GET | /{package_name}/releases | Get all versions | No |
| GET | /{package_name}/releases/tags/{version} | Get specific version | No |
| GET | /{package_name}/releases/latest | Get latest version | No |
| GET | /search | Search packages | No |
| DELETE | /{package_name}/releases/tags/{version} | Delete specific version | Yes |
| GET | /{package_name}/zipball/{version} | Download package | No |
| POST | /{package_name}/maintainers | Add maintainer | Yes |
| DELETE | /{package_name}/maintainers/{username} | Remove maintainer | Yes |

### Detailed API Information

#### Register New User

- Method: POST
- Path: /register
- Description: Register a new user account
- Request Body:
  ```json
  {
    "username": "string",
    "password": "string",
    "email": "string"
  }
  ```
- Response:
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

#### User Login

- Method: POST
- Path: /login
- Description: User login and obtain authentication token
- Request Body:
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- Response:
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

#### User Logout

- Method: POST
- Path: /logout
- Description: User logout, invalidate current token
- Request Headers: 
  - Authorization: Bearer {token}
- Response:
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

#### Refresh Authentication Token

- Method: POST
- Path: /refresh_token
- Description: Refresh user's authentication token
- Request Headers: 
  - Authorization: Bearer {token}
- Response:
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

#### Change Password

- Method: POST
- Path: /change_password
- Description: Change user password
- Request Headers: 
  - Authorization: Bearer {token}
- Request Body:
  ```json
  {
    "old_password": "string",
    "new_password": "string"
  }
  ```
- Response:
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

#### Create/Update Package

- Method: POST
- Path: /releases
- Description: Create new package or update existing package
- Request Headers: 
  - Authorization: Bearer {token}
- Request Body:
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
- Response:
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

#### Upload Package File

- Method: POST
- Path: /upload/{upload_id}
- Description: Upload package file
- Request Headers: 
  - Authorization: Bearer {token}
- Request Body: 
  - Form data containing a file field named "package"
- Response:
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

#### Get All Versions

- Method: GET
- Path: /{package_name}/releases
- Description: Get all version information for a specific package
- Response:
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

Certainly! I'll continue with the translation of the remaining API endpoints:

```markdown
#### Get Latest Version

- Method: GET
- Path: /{package_name}/releases/latest
- Description: Get information for the latest version of a specific package
- Response:
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

#### Search Packages

- Method: GET
- Path: /search
- Description: Search for packages
- Query Parameters:
  - search: Search keyword
- Response:
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

#### Delete Specific Version

- Method: DELETE
- Path: /{package_name}/releases/tags/{version}
- Description: Delete a specific version of a package
- Request Headers: 
  - Authorization: Bearer {token}
- Response:
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

#### Download Package

- Method: GET
- Path: /{package_name}/zipball/{version}
- Description: Download a specific version of a package
- Response:
  - 200 OK
    - Content-Type: application/zip
    - Body: Binary file content
  - 404 Not Found
    ```json
    {
      "error": "Package or version not found"
    }
    ```

#### Add Maintainer

- Method: POST
- Path: /{package_name}/maintainers
- Description: Add a maintainer to a specific package
- Request Headers: 
  - Authorization: Bearer {token}
- Request Body:
  ```json
  {
    "username": "string",
    "role": "string"
  }
  ```
- Response:
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

#### Remove Maintainer

- Method: DELETE
- Path: /{package_name}/maintainers/{username}
- Description: Remove a maintainer from a specific package
- Request Headers: 
  - Authorization: Bearer {token}
- Response:
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

### Signature Authentication

To enhance security and prevent replay attacks, we have implemented an enhanced signature authentication mechanism. Each API request that requires authentication should include the following headers:

- `X-Api-Key`: API key (assigned to the client by the server)
- `X-Timestamp`: Current timestamp (Unix timestamp)
- `X-Nonce`: Randomly generated string to ensure request uniqueness
- `X-Signature`: Request signature

#### Signature Generation Method

1. Concatenate the request method, request path, timestamp, nonce, and request body (if any) into a string
2. Use the API key to perform HMAC-SHA256 encryption on this string
3. Convert the encryption result to Base64 encoding

#### Server Verification Steps

1. Check if the timestamp is within the allowed time range (within 10 seconds)
2. Verify that the nonce has not been used in the past 10 seconds
3. Generate the signature using the same method
4. Compare the generated signature with the signature in the request

#### Python Implementation Example

```python
import hmac
import hashlib
import base64
import time
import uuid
from collections import deque

# For storing recently used nonces
USED_NONCES = deque(maxlen=1000)  # Limit the number of stored nonces to avoid unlimited growth

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
    
    # Check if timestamp is within 10 seconds
    if abs(int(timestamp) - current_time) > 10:
        return False
    
    # Check if nonce has been used
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
        # If signature verification passes, add nonce to the used list
        USED_NONCES.append(nonce)
        return True
    
    return False

# Client usage example
def client_request(method, path, body, api_key):
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())  # Generate random nonce
    
    signature = generate_signature(method, path, timestamp, nonce, body, api_key)
    
    headers = {
        'X-Api-Key': api_key,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': signature
    }
    
    # This should be an actual HTTP request
    print(f"Sending request with headers: {headers}")
```

#### Notes

1. Time Synchronization: Ensure that the clocks of the client and server are synchronized, otherwise requests may be incorrectly rejected.

2. Nonce Storage: In high-concurrency environments, consider using distributed caching (such as Redis) to store recently used nonces to ensure system scalability.

3. Periodic Cleaning: Periodically clean expired nonce records to prevent unlimited memory growth.

4. Load Balancing: If load balancing is used, ensure that nonce verification remains consistent across all servers.

5. HTTPS: Although the signature mechanism provides some security, it is still strongly recommended to transmit all API requests via HTTPS to prevent man-in-the-middle attacks.

6. API Key Protection: Ensure that API keys are properly safeguarded and not hard-coded or exposed in client-side code or public places.

By implementing this enhanced signature authentication mechanism, we can effectively prevent replay attacks and improve the security and integrity of API calls. Each request has uniqueness (guaranteed by the nonce) and time sensitivity (guaranteed by the timestamp), greatly increasing the difficulty of forging or replaying valid requests.

## Notes

- All APIs requiring authentication need to include the `Authorization` field in the request header, with its value being the token obtained during login.
- This project includes rate limiting functionality to prevent API abuse.
- Please ensure that more secure configurations are used in production environments, such as using HTTPS and changing default keys.


      