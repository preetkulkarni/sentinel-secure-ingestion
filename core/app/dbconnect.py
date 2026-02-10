"""Database connection management for MongoDB.

This module handles the asynchronous connection lifecycle for MongoDB using Motor.
It provides functions to connect, disconnect, and retrieve database instances
for dependency injection.
"""

import logging
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

# Setup structured logging
logger = logging.getLogger("sentinel.db")


class Database:
    """A simple container for the MongoDB client instance."""
    client: AsyncIOMotorClient = None


db = Database()


async def get_database():
    """Retrieves the active database object defined in settings.

    This function is designed to be used as a dependency in FastAPI endpoints.

    Returns:
        AsyncIOMotorDatabase: The specific database instance (e.g., 'sentinel_db')
        derived from the active client.

    Raises:
        ConnectionError: If the database client has not been initialized
            (i.e., connect_to_mongo() was not called).
    """
    if db.client is None:
        logger.error("Attempted to access database before initialization.")
        raise ConnectionError("Database client is not initialized.")

    return db.client[settings.MONGO_DB_NAME]


async def connect_to_mongo():
    """Initializes the MongoDB connection pool.

    This function attempts to create an AsyncIOMotorClient and verifies
    connectivity by pinging the admin database. It should be called during
    the application startup lifespan event.

    Raises:
        Exception: Propagates any exception encountered during the connection
            process (e.g., ConfigurationError, ConnectionFailure) to ensure
            the application does not start in a broken state.
    """
    try:
        logger.info("🔌 Connecting to MongoDB...")

        uri = settings.MONGO_URI.get_secret_value()

        db.client = AsyncIOMotorClient(uri, maxPoolSize=10, minPoolSize=10)

        # Verify connection
        await db.client.admin.command("ping")
        logger.info(f"✅ Connected to MongoDB (DB: {settings.MONGO_DB_NAME})")

    except Exception as e:
        logger.critical(f"❌ MongoDB Connection Error: {e}")
        # We re-raise the exception so main.py knows startup failed
        raise e


async def close_mongo_connection():
    """Closes the MongoDB connection pool.

    This function ensures that all database connections are gracefully closed.
    It should be called during the application shutdown lifespan event.
    """
    if db.client:
        db.client.close()
        logger.info("🛑 Closed MongoDB connection")