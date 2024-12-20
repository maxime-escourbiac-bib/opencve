from airflow.models.baseoperator import BaseOperator
from git.objects.commit import Commit
from includes.constants import CERTIST_LOCAL_REPO
from includes.utils import list_commits

#This is needed to avoid the error: django.core.exceptions.AppRegistryNotReady: Apps aren't loaded yet.
import django
django.setup()

from advancedcve.models import CertIstProduct

class ProcessCertISTProductsOperator(BaseOperator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
    
    def execute(self, context):
        commits = list_commits(
            logger=self.log,
            start=context.get("data_interval_start"),
            end=context.get("data_interval_end"),
            repo_path=CERTIST_LOCAL_REPO
        )

        for product in CertIstProduct.objects.all() :
            self.log.info(product)


class ProcessCertISTAdvisoriesOperator(BaseOperator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
    
    def execute(self, context):
        commits = list_commits(
            logger=self.log,
            start=context.get("data_interval_start"),
            end=context.get("data_interval_end"),
            repo_path=CERTIST_LOCAL_REPO
        )

        # Process products.
        self.log.info("Processing advisories commits")

class ProcessCertISTAlertOperator(BaseOperator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
    
    def execute(self, context):
        commits = list_commits(
            logger=self.log,
            start=context.get("data_interval_start"),
            end=context.get("data_interval_end"),
            repo_path=CERTIST_LOCAL_REPO
        )

        # Process products.
        self.log.info("Processing alerts commits")


