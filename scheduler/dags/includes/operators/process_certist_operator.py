from airflow.models.baseoperator import BaseOperator
from git.objects.commit import Commit
from includes.constants import CERTIST_LOCAL_REPO

from includes.utils import list_commits


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

        # Process products.
        self.log.info("Processing products commits")
        product_update = False
        for commit in commits:
            self.log.info(commit)
            
        
        if product_update:
            self.log.info("Products have been updated, processing...")


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


