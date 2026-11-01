"""Gen2 Cloud Function entry point, following Google's billing notification pattern."""

import os

import functions_framework
from guard import handle_event


@functions_framework.cloud_event
def cap_spending(cloud_event):
    handle_event(
        cloud_event,
        project_id=os.environ["TARGET_PROJECT_ID"],
        budget_name=os.environ["BUDGET_NAME"],
    )
