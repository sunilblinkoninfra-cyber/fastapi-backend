print(">>> RUNNING app.py <<<")
from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Swagger Test API",
    version="1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

@app.get("/")
def root():
    return {"status": "ok"}

@app.get("/openapi.json")
def openapi():
    return JSONResponse(
        get_openapi(
            title=app.title,
            version=app.version,
            routes=app.routes,
        )
    )

@app.get("/docs")
def docs():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Swagger Test",
    )

