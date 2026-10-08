import datetime
import enum
import uuid

from sqlmodel import Field, SQLModel


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class JobStatus(str, enum.Enum):
    AWAITING_MODE = "AWAITING_MODE"  # uploaded, waiting for the user to pick an analysis mode
    QUEUED = "QUEUED"
    PARSING = "PARSING"
    DEVICE_CHECK = "DEVICE_CHECK"
    INSTALLING = "INSTALLING"
    MOBSF_DAST = "MOBSF_DAST"  # sast_dast / sast_dast_burp: MobSF's own dynamic-analysis phase
    CA_TRUST = "CA_TRUST"
    PROXY_SET = "PROXY_SET"
    FRIDA_ATTACH = "FRIDA_ATTACH"
    STATIC_PATCH = "STATIC_PATCH"
    AWAITING_BURP_CONFIRM = "AWAITING_BURP_CONFIRM"  # sast_dast_burp only
    DONE = "DONE"
    FAILED = "FAILED"


class AnalysisMode(str, enum.Enum):
    SAST = "sast"
    SAST_DAST = "sast_dast"
    SAST_DAST_BURP = "sast_dast_burp"


class Job(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime.datetime = Field(default_factory=utc_now)
    updated_at: datetime.datetime = Field(default_factory=utc_now)

    original_filename: str
    stored_path: str
    package_name: str | None = None
    is_split_apk: bool = False
    is_flutter: bool = False

    analysis_mode: AnalysisMode | None = None
    device_target_type: str | None = None  # "emulator" | "physical" - user's per-job device choice
    device_target_ip: str | None = None  # only meaningful when device_target_type == "physical"
    status: JobStatus = Field(default=JobStatus.AWAITING_MODE)
    bypass_method: str | None = None  # "frida" | "static_patch" | None
    failure_reason: str | None = None

    mobsf_report_url: str | None = None
    mobsf_dynamic_report_url: str | None = None
    device_serial: str | None = None


class JobLogLine(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    job_id: uuid.UUID = Field(foreign_key="job.id", index=True)
    timestamp: datetime.datetime = Field(default_factory=utc_now)
    level: str = "info"  # info | warn | error
    message: str
