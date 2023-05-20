from pydantic import BaseModel
from sqlalchemy import create_engine, Engine, Connection
from typing import Optional
from sqlalchemy import create_engine, text
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from jsql import SqlProxy
from ...conf import settings
from ..model import AttackClassType, Report, AttackClassReports
from typing import List


class ReportingService(BaseModel):
    db_connection: Optional[Connection] = None

    def init_database(self) -> Engine:
        engine = create_engine(settings.DATABASE_NAME, echo=True)

        Base = declarative_base()

        class ReportSchema(Base):
            __tablename__ = "Report"

            id = Column(Integer, primary_key=True, autoincrement=True)
            endpoint = Column(String)
            attack_class = Column(Integer)
            response_body = Column(String)
            request_body = Column(String)

            def __init__(
                self,
                endpoint: str,
                attack_class: AttackClassType,
                response_body: str,
                request_body: str,
            ):
                self.endpoint = endpoint
                self.attack_class = attack_class
                self.request_body = request_body
                self.response_body = response_body

        Base.metadata.create_all(engine)

        return engine

    def init_connection(self) -> None:
        if not self.db_connection:
            self.db_connection = self.init_database().connect()

    def insert(self, report: Report) -> int:
        self.init_connection()

        report.attack_class = report.attack_class.value
        transaction = self.db_connection.begin()

        report_id = SqlProxy(
            self.db_connection.execute(
                text(
                    """
            INSERT INTO Report
                (endpoint,attack_class,response_body,request_body)
            VALUES
                (:endpoint,:attack_class,:response_body,:request_body)
            """,
                ),
                report.dict(),
            )
        ).lastrowid

        transaction.commit()
        return report_id

    def retrive(self) -> List[AttackClassReports]:
        self.init_connection()

        transaction = self.db_connection.begin()

        data = SqlProxy(
            self.db_connection.execute(
                text(
                    """
                    SELECT * FROM Report ORDER BY attack_class
                    """,
                ),
            )
        ).dicts()
        transaction.commit()

        report_groups: List[AttackClassReports] = [
            AttackClassReports(type=type) for type in AttackClassType
        ]

        [
            report_groups[report["attack_class"] - 1].reports.append(Report(**report))
            for report in data
        ]

        return report_groups

    class Config:
        arbitrary_types_allowed = True
