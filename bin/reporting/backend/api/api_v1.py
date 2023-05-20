from fastapi import APIRouter, status, Response

from ..service import ReportingServiceV1
from ..model import Report, AttackClassReports
from typing import List


def ReportingAPI() -> APIRouter:
    api_router = APIRouter(prefix="/api/v1", tags=["API-v1"])
    RS = ReportingServiceV1()

    @api_router.get("/get_reports", response_model=List[AttackClassReports])
    def get_reports() -> List[AttackClassReports]:
        return RS.retrive()

    @api_router.post(
        "/insert_report", response_model=str, status_code=status.HTTP_201_CREATED
    )
    def insert_report(response: Response, report: Report):
        RS.init_connection()

        return RS.insert(report)

    return api_router
