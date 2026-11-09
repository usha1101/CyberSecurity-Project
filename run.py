import uvicorn
from app.config import settings

if __name__ == "__main__":
    print(f"Starting ZeroGuard ASGI Server on http://{settings.HOST}:{settings.PORT}")
    print(f"Swagger Documentation available at http://localhost:{settings.PORT}/docs")
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENVIRONMENT == "development",
        log_level=settings.LOG_LEVEL.lower(),
    )

