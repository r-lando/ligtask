from pydantic import BaseModel


class GitHubAssessmentRequest(BaseModel):
    repository_url: str