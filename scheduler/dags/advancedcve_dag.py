import logging
import pendulum

from airflow.configuration import conf
from airflow.decorators import dag
from airflow.utils.task_group import TaskGroup
from includes.operators.fetch_operator import GitFetchOperator
from includes.operators.process_certist_operator import ProcessCertISTProductsOperator, ProcessCertISTAdvisoriesOperator, ProcessCertISTAlertOperator

logger = logging.getLogger(__name__)

# The catchup is set to True, so we allow the user to update his start_date
# value to match the installation date of his own OpenCVE instance.
start_date = pendulum.from_format(conf.get("opencve", "start_date"), "YYYY-MM-DD")


@dag(
    schedule="0 * * * *",
    start_date=start_date,
    catchup=True,
    max_active_runs=1,
)
def advancedcve():
    with TaskGroup(group_id="certist") as certist_group:

        process_certist_tasks = [
            ProcessCertISTProductsOperator(task_id="process_certist_products"),
            ProcessCertISTAdvisoriesOperator(task_id="process_certist_advisories"),
            ProcessCertISTAlertOperator(task_id="process_certist_alerts")
        ]

        GitFetchOperator(task_id="fetch_certist", kind="certist") >> process_certist_tasks


advancedcve()
