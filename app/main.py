from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.routes import router

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("zeroguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown hooks."""
    logger.info("Initializing ZeroGuard AI-Powered Zero-Day Detection Engine...")
    logger.info(f"Target Environment: {settings.ENVIRONMENT}")
    logger.info(f"Active Free-Tier LLM Provider: {settings.LLM_PROVIDER}")
    logger.info(f"Hack Fest 2026 Track: Secure Sphere")
    yield
    logger.info("Shutting down ZeroGuard Engine...")


app = FastAPI(
    title="ZeroGuard — Zero-Day & Logic Flaw Detection Engine",
    description=(
        "Next-generation AI vulnerability detection engine built for **Hack Fest 2026 (Track: Secure Sphere)**. "
        "Goes beyond signature-based linters (Bandit/Semgrep) to detect subtle multi-step zero-day logic flaws, "
        "broken state invariants, and untrusted taint propagation paths with verified self-healing diff patches "
        "and standard CVSS v3.1 dynamic scoring."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for Vite/React frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount core API router for both /api/v1 and /api routes
app.include_router(router)

# Compatibility router for /api/scan, /api/health, etc.
api_compat_router = APIRouter(prefix="/api", tags=["ZeroGuard Compatibility"])
api_compat_router.add_api_route("/scan", router.routes[0].endpoint, methods=["POST"], response_model=router.routes[0].response_model)
api_compat_router.add_api_route("/verify-patch", router.routes[1].endpoint, methods=["POST"], response_model=router.routes[1].response_model)
api_compat_router.add_api_route("/apply-diff", router.routes[2].endpoint, methods=["POST"])
api_compat_router.add_api_route("/providers", router.routes[3].endpoint, methods=["GET"], response_model=router.routes[3].response_model)
api_compat_router.add_api_route("/health", router.routes[4].endpoint, methods=["GET"], response_model=router.routes[4].response_model)
app.include_router(api_compat_router)


@app.get("/", tags=["Root"])
async def root():
    return {
        "engine": "ZeroGuard AI-Powered Zero-Day Engine",
        "competition": "Hack Fest 2026",
        "track": "Secure Sphere",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health",
        "providers": "/api/v1/providers",
    }

