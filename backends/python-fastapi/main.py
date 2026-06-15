"""
backends/python-fastapi/main.py
Test backend for mini-waf — listens on port 33334.

Endpoints:
  GET  /                  catch_all tier
  GET  /health            health check
  ANY  /api/echo          echoes method/path/headers/query/body
  GET  /api/hello         high tier
  GET  /api/users         high tier
  POST /login             critical tier
  GET  /user/{user_id}    high tier
  GET  /static/test.txt   medium tier
"""

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
import uvicorn

app = FastAPI(title="waf-test-backend", version="0.1.0")


@app.get("/")
async def root():
    return {"backend": "fastapi", "message": "hello from FastAPI backend"}


@app.get("/health")
async def health():
    return {"healthy": True}


@app.api_route("/api/echo", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def echo(request: Request):
    body = await request.body()
    return {
        "method": request.method,
        "path": request.url.path,
        "headers": dict(request.headers),
        "query": dict(request.query_params),
        "body": body.decode("utf-8", errors="replace"),
    }


@app.get("/api/hello")
async def hello():
    return {"message": "hello from FastAPI"}


@app.get("/api/users")
async def get_users():
    return [
        {"id": 1, "name": "Alice", "backend": "fastapi"},
        {"id": 2, "name": "Bob", "backend": "fastapi"},
    ]


@app.post("/login")
async def login(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    username = data.get("username", "unknown")
    return {"token": "test-token-fastapi", "user": username}


@app.get("/user/{user_id}")
async def get_user(user_id: str):
    return {"id": user_id, "name": f"User {user_id}", "backend": "fastapi"}


@app.get("/static/test.txt", response_class=PlainTextResponse)
async def static_file():
    return "Hello from static file (FastAPI backend)\n"


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=33334, log_level="info")
