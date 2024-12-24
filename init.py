import argparse
import os
import sys
from datetime import datetime

def create_sqlite_tables(cursor):
    cursor.executescript('''
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS Packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(64) NOT NULL UNIQUE,
        type TEXT CHECK(type IN ('project', 'component', 'plugin')) NOT NULL,
        description TEXT,
        home VARCHAR(255),
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        downloads_count INTEGER DEFAULT 0,
        is_deprecated BOOLEAN DEFAULT 0,
        latest_version_id INTEGER,
        FOREIGN KEY (latest_version_id) REFERENCES Versions(id)
    );

    CREATE TABLE IF NOT EXISTS Versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id INTEGER,
        version VARCHAR(20) NOT NULL,
        edition VARCHAR(10) NOT NULL,
        description TEXT,
        readme TEXT,
        zipball_url VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        grayscale FLOAT DEFAULT 1,
        status TEXT DEFAULT 'pending',
        downloads_count INTEGER DEFAULT 0,
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        UNIQUE (package_id, version)
    );

    CREATE TABLE IF NOT EXISTS Providers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(50) NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS PackageProviders (
        package_id INTEGER,
        provider_id INTEGER,
        PRIMARY KEY (package_id, provider_id),
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (provider_id) REFERENCES Providers(id)
    );

    CREATE TABLE IF NOT EXISTS Tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(50) NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS PackageTags (
        package_id INTEGER,
        tag_id INTEGER,
        PRIMARY KEY (package_id, tag_id),
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (tag_id) REFERENCES Tags(id)
    );

    CREATE TABLE IF NOT EXISTS Services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id INTEGER,
        service_name VARCHAR(100) NOT NULL,
        permissions TEXT,
        FOREIGN KEY (package_id) REFERENCES Packages(id)
    );

    CREATE TABLE IF NOT EXISTS Commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id INTEGER,
        command_name VARCHAR(50) NOT NULL,
        description TEXT,
        FOREIGN KEY (package_id) REFERENCES Packages(id)
    );

    CREATE TABLE IF NOT EXISTS Properties (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id INTEGER,
        property_name VARCHAR(50) NOT NULL,
        property_value TEXT,
        FOREIGN KEY (package_id) REFERENCES Packages(id)
    );

    CREATE TABLE IF NOT EXISTS Tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expired_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES Users(id)
    );

    CREATE TABLE IF NOT EXISTS PackageMaintainers (
        package_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT NOT NULL,
        PRIMARY KEY (package_id, user_id),
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (user_id) REFERENCES Users(id)
    );

    CREATE TABLE IF NOT EXISTS Dependencies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id INTEGER,
        dependency_package_id INTEGER,
        version_constraint TEXT,
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (dependency_package_id) REFERENCES Packages(id)
    );

    CREATE TABLE IF NOT EXISTS Changelogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version_id INTEGER,
        changelog TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (version_id) REFERENCES Versions(id)
    );

    CREATE TABLE IF NOT EXISTS PackageRatings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id INTEGER,
        user_id INTEGER,
        rating INTEGER CHECK(rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (user_id) REFERENCES Users(id),
        UNIQUE (package_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS AuditLogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES Users(id)
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_packages_name ON Packages(name);
    CREATE INDEX IF NOT EXISTS idx_packages_type ON Packages(type);
    CREATE INDEX IF NOT EXISTS idx_packages_create_time ON Packages(create_time);
    CREATE INDEX IF NOT EXISTS idx_versions_package_id ON Versions(package_id);
    CREATE INDEX IF NOT EXISTS idx_versions_created_at ON Versions(created_at);
    CREATE INDEX IF NOT EXISTS idx_packagemaintainers_user_id ON PackageMaintainers(user_id);
    CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON Tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_dependencies_package_id ON Dependencies(package_id);
    CREATE INDEX IF NOT EXISTS idx_changelogs_version_id ON Changelogs(version_id);
    CREATE INDEX IF NOT EXISTS idx_packageratings_package_id ON PackageRatings(package_id);
    CREATE INDEX IF NOT EXISTS idx_auditlogs_user_id ON AuditLogs(user_id);
    CREATE INDEX IF NOT EXISTS idx_auditlogs_created_at ON AuditLogs(created_at);
    ''')

def create_mysql_tables(cursor):
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Packages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(64) NOT NULL UNIQUE,
        type ENUM('project', 'component', 'plugin') NOT NULL,
        description TEXT,
        home VARCHAR(255),
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        downloads_count INT DEFAULT 0,
        is_deprecated BOOLEAN DEFAULT FALSE,
        latest_version_id INT,
        FOREIGN KEY (latest_version_id) REFERENCES Versions(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Versions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        package_id INT,
        version VARCHAR(20) NOT NULL,
        edition VARCHAR(10) NOT NULL,
        description TEXT,
        readme TEXT,
        zipball_url VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        grayscale FLOAT DEFAULT 1,
        status VARCHAR(20) DEFAULT 'pending',
        downloads_count INT DEFAULT 0,
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        UNIQUE (package_id, version)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Providers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS PackageProviders (
        package_id INT,
        provider_id INT,
        PRIMARY KEY (package_id, provider_id),
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (provider_id) REFERENCES Providers(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Tags (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS PackageTags (
        package_id INT,
        tag_id INT,
        PRIMARY KEY (package_id, tag_id),
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (tag_id) REFERENCES Tags(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Services (
        id INT AUTO_INCREMENT PRIMARY KEY,
        package_id INT,
        service_name VARCHAR(100) NOT NULL,
        permissions TEXT,
        FOREIGN KEY (package_id) REFERENCES Packages(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Commands (
        id INT AUTO_INCREMENT PRIMARY KEY,
        package_id INT,
        command_name VARCHAR(50) NOT NULL,
        description TEXT,
        FOREIGN KEY (package_id) REFERENCES Packages(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Properties (
        id INT AUTO_INCREMENT PRIMARY KEY,
        package_id INT,
        property_name VARCHAR(50) NOT NULL,
        property_value TEXT,
        FOREIGN KEY (package_id) REFERENCES Packages(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expired_at TIMESTAMP NULL,
        FOREIGN KEY (user_id) REFERENCES Users(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS PackageMaintainers (
        package_id INT NOT NULL,
        user_id INT NOT NULL,
        role VARCHAR(20) NOT NULL,
        PRIMARY KEY (package_id, user_id),
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (user_id) REFERENCES Users(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Dependencies (
        id INT AUTO_INCREMENT PRIMARY KEY,
        package_id INT,
        dependency_package_id INT,
        version_constraint VARCHAR(50),
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (dependency_package_id) REFERENCES Packages(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Changelogs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        version_id INT,
        changelog TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (version_id) REFERENCES Versions(id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS PackageRatings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        package_id INT,
        user_id INT,
        rating INT CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (package_id) REFERENCES Packages(id),
        FOREIGN KEY (user_id) REFERENCES Users(id),
        UNIQUE (package_id, user_id)
    ) ENGINE=InnoDB;
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS AuditLogs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        action VARCHAR(255),
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES Users(id)
    ) ENGINE=InnoDB;
    ''')

    # Indexes
    cursor.execute('CREATE INDEX idx_packages_name ON Packages(name);')
    cursor.execute('CREATE INDEX idx_packages_type ON Packages(type);')
    cursor.execute('CREATE INDEX idx_packages_create_time ON Packages(create_time);')
    cursor.execute('CREATE INDEX idx_versions_package_id ON Versions(package_id);')
    cursor.execute('CREATE INDEX idx_versions_created_at ON Versions(created_at);')
    cursor.execute('CREATE INDEX idx_packagemaintainers_user_id ON PackageMaintainers(user_id);')
    cursor.execute('CREATE INDEX idx_tokens_user_id ON Tokens(user_id);')
    cursor.execute('CREATE INDEX idx_dependencies_package_id ON Dependencies(package_id);')
    cursor.execute('CREATE INDEX idx_changelogs_version_id ON Changelogs(version_id);')
    cursor.execute('CREATE INDEX idx_packageratings_package_id ON PackageRatings(package_id);')
    cursor.execute('CREATE INDEX idx_auditlogs_user_id ON AuditLogs(user_id);')
    cursor.execute('CREATE INDEX idx_auditlogs_created_at ON AuditLogs(created_at);')

def init_sqlite(db_path):
    import sqlite3
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    create_sqlite_tables(cursor)
    conn.commit()
    conn.close()
    print(f"SQLite database initialized at {db_path}")

def init_mysql(host, user, password, database):
    import mysql.connector
    conn = mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database
    )
    cursor = conn.cursor()
    create_mysql_tables(cursor)
    conn.commit()
    conn.close()
    print(f"MySQL database initialized at {host}/{database}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize the database for the Serverless Registry.")
    parser.add_argument("--type", choices=["sqlite", "mysql"], required=True, help="Type of database to use")
    parser.add_argument("--path", help="Path for SQLite database file")
    parser.add_argument("--host", help="Host for MySQL database")
    parser.add_argument("--user", help="User for MySQL database")
    parser.add_argument("--password", help="Password for MySQL database")
    parser.add_argument("--database", help="Database name for MySQL")

    args = parser.parse_args()

    if args.type == "sqlite":
        if not args.path:
            print("Error: --path is required for SQLite")
            sys.exit(1)
        init_sqlite(args.path)
    elif args.type == "mysql":
        if not all([args.host, args.user, args.password, args.database]):
            print("Error: --host, --user, --password, and --database are required for MySQL")
            sys.exit(1)
        init_mysql(args.host, args.user, args.password, args.database)