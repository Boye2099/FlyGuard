import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = BASE_DIR / "flyguard.db"


def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def create_tables():
    connection = get_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            domain TEXT NOT NULL,
            url TEXT NOT NULL,
            protocol TEXT NOT NULL,
            is_https INTEGER NOT NULL,

            links INTEGER NOT NULL,
            scripts INTEGER NOT NULL,
            images INTEGER NOT NULL,
            forms INTEGER NOT NULL,
            iframes INTEGER NOT NULL,
            resources INTEGER NOT NULL,

            third_party_domains TEXT NOT NULL,

            password_fields INTEGER NOT NULL,
            insecure_forms INTEGER NOT NULL,
            mixed_content INTEGER NOT NULL,

            inline_scripts INTEGER NOT NULL,
            external_scripts INTEGER NOT NULL,

            has_csp INTEGER NOT NULL,
            cookie_count INTEGER NOT NULL,

            headers TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    connection.commit()

    connection.close()