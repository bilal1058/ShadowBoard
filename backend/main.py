import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, Response
from app.db.session import init_db, get_db
from app.api.router import api_router
from app.target_app.app import app as target_app, support_ui
from app.internal_rag.app import app as internal_rag_app, internal_rag_ui

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB schema on startup
    await init_db()
    
    # Register / synchronize the two reference targets
    from app.db.session import DB_PATH
    import aiosqlite
    import json
    async with aiosqlite.connect(DB_PATH) as db:
        from app.api.endpoints.policies import default_policy_for_target_type
        reference_targets = [
            {
                "name": "Meridian Support Assistant",
                "base_url": "http://127.0.0.1:8000/target-app",
                "target_type": "EXTERNAL_SUPPORT",
                "capabilities": {
                    "chat": True,
                    "rag": False,
                    "tools": False,
                    "data_access": False,
                    "has_rag": False,
                    "has_tools": False,
                    "has_memory": False,
                    "tool_names": []
                },
            },
            {
                "name": "Meridian Internal Knowledge Assistant",
                "base_url": "http://127.0.0.1:8000/internal-rag",
                "target_type": "INTERNAL_RAG",
                "capabilities": {
                    "chat": True,
                    "rag": True,
                    "tools": True,
                    "data_access": True,
                    "has_rag": True,
                    "has_tools": True,
                    "has_memory": False,
                    "tool_names": ["get_invoice", "send_email"]
                },
            },
        ]
        for target in reference_targets:
            cursor = await db.execute("SELECT id FROM targets WHERE base_url = ?", (target["base_url"],))
            row = await cursor.fetchone()
            if row:
                target_id = row[0]
                await db.execute(
                    "UPDATE targets SET name = ?, target_type = ?, capabilities_json = ? WHERE id = ?",
                    (target["name"], target["target_type"], json.dumps(target["capabilities"]), target_id),
                )
                policy_dict = default_policy_for_target_type(target["target_type"])
                cursor = await db.execute("SELECT COUNT(*) FROM policies WHERE target_id = ?", (target_id,))
                if (await cursor.fetchone())[0] == 0:
                    await db.execute(
                        "INSERT INTO policies (target_id, policy_json, taxonomy, taxonomy_version) VALUES (?, ?, ?, ?)",
                        (target_id, json.dumps(policy_dict), "OWASP", "2025"),
                    )
                else:
                    await db.execute(
                        "UPDATE policies SET policy_json = ?, taxonomy = ?, taxonomy_version = ? WHERE target_id = ?",
                        (json.dumps(policy_dict), "OWASP", "2025", target_id),
                    )
            else:
                cursor = await db.execute(
                    "INSERT INTO targets (name, base_url, model_name, target_type, target_mode, capabilities_json) VALUES (?, ?, ?, ?, ?, ?)",
                    (target["name"], target["base_url"], "qwen-flash", target["target_type"], "INSTRUMENTED", json.dumps(target["capabilities"])),
                )
                target_id = cursor.lastrowid
                await db.execute(
                    "INSERT INTO policies (target_id, policy_json, taxonomy, taxonomy_version) VALUES (?, ?, ?, ?)",
                    (target_id, json.dumps(default_policy_for_target_type(target["target_type"])), "OWASP", "2025"),
                )
        await db.commit()
    yield

app = FastAPI(
    title="ShadowBoard — Policy-Driven AI Application Security Testing",
    description="Executable security policy evaluation with trace-driven evidence verification.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Direct routes for targets to guarantee immediate rendering without 307 trailing-slash issues
@app.get("/target-app", response_class=HTMLResponse)
@app.get("/target-app/", response_class=HTMLResponse)
async def serve_target_app_page():
    return await support_ui()

@app.get("/internal-rag", response_class=HTMLResponse)
@app.get("/internal-rag/", response_class=HTMLResponse)
async def serve_internal_rag_page():
    return await internal_rag_ui()

# Mount API routes
app.include_router(api_router)

# Mount self-hosted sub-apps for API routing (e.g. /target-app/chat, /internal-rag/chat)
app.mount("/target-app", target_app)
app.mount("/internal-rag", internal_rag_app)

# Serve Frontend directory (prioritize top-level frontend/ directory, fallback to backend/static)
root_frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
backend_static_dir = os.path.join(os.path.dirname(__file__), "static")
frontend_static_dir = root_frontend_dir if os.path.exists(root_frontend_dir) else backend_static_dir

if os.path.exists(frontend_static_dir):
    app.mount("/static", StaticFiles(directory=frontend_static_dir), name="static")

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    svg_icon = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#dc2626"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5zm0 2.18l7 3.89v4.93c0 4.54-3.14 8.79-7 9.94-3.86-1.15-7-5.4-7-9.94V8.07l7-3.89z"/></svg>"""
    return Response(content=svg_icon, media_type="image/svg+xml")

@app.get("/")
async def root():
    index_file = os.path.join(frontend_static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse(content="<h1>ShadowBoard Security Engine Active</h1><p>API docs at <a href='/docs'>/docs</a></p>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
