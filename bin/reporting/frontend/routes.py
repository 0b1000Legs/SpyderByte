from fastapi import Request, APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .utility import normalize_text
import requests
from ..conf import settings
from ..backend.model import AttackClassReports
from typing import List


def ReportingRouter(templates: Jinja2Templates) -> APIRouter:
    page_router = APIRouter(tags=["UI"])

    @page_router.get("/", response_class=HTMLResponse)
    def index(request: Request):
        report_groups: List[AttackClassReports] = requests.get(
            f"http://{settings.HOST}:{settings.REPORTING_PORT}/api/v1/get_reports"
        ).json()

        return templates.TemplateResponse(
            "view/index.html",
            {
                "utility": {"normalize_text": normalize_text},
                "request": request,
                "report_groups": report_groups,
            },
        )

    @page_router.get("/insecure_direct_object_references", response_class=HTMLResponse)
    def insecure_direct_object_references(request: Request):
        # return templates.TemplateResponse(
        #     "view/insecure_direct_object_references.html",
        #     {
        #         "request": request,
        #     },
        # )
        return RedirectResponse("https://portswigger.net/web-security/access-control/idor")


    @page_router.get("/server-side_request_forgery", response_class=HTMLResponse)
    def server_side_request_forgery(request: Request):
        # return templates.TemplateResponse(
        #     "view/server-side_request_forgery.html",
        #     {
        #         "request": request,
        #     },
        # )
        return RedirectResponse("https://www.hacksplaining.com/prevention/ssrf")


    @page_router.get("/flawed_jwt_signature_verification")
    def flawed_jwt_signature_verification(request: Request):
        # return templates.TemplateResponse(
        #     "view/flawed_jwt_signature_verification.html",
        #     {
        #         "request": request,
        #     },
        # )
        return RedirectResponse("https://portswigger.net/web-security/jwt")


    return page_router
