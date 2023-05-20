from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import sass

from pathlib import Path


from bin.reporting.frontend import ReportingRouter
from bin.reporting.backend.api import ReportingAPIV1
from bin.reporting.conf import settings


app = FastAPI()

templates = Jinja2Templates(directory=f"{Path(__file__).parent}/frontend/templates")

app.include_router(ReportingRouter(templates))
app.include_router(ReportingAPIV1())

sass.compile(
    dirname=(
        f"{Path(__file__).parent}/frontend/static/sass",
        f"{Path(__file__).parent}/frontend/static/css",
    )
)

app.mount(
    "/static",
    StaticFiles(
        directory=f"{Path(__file__).parent}/frontend/static",
    ),
    name="static",
)


def start_reporting_ui():
    uvicorn.run(
        f"{__name__}:app",
        host=settings.HOST,
        port=settings.REPORTING_PORT,
        reload=settings.DEV_MODE,
    )
