from django.conf import settings

from opencve.commands import BaseCommand
from advancedcve.models import CertIstAdvisory, CertIstAlert, CertIstProduct
from cves.models import Cve

import pathlib


class Command(BaseCommand):
    CERTIST_PATH = settings.CERTIST_REPO_PATH
    
    """ Check if the CERT-IST repository exists. """
    def kb_repo_exist(self):
        return pathlib.Path.exists(pathlib.Path(self.CERTIST_PATH))

    """ Insert CERT-IST products into the database. """
    def insert_products(self):
        assets_catalog = CertIstProduct.get_all_products_xml_node()
        print(f"Found {self.blue(len(assets_catalog))} products in the CERT-IST repository")

        for asset_catalog in assets_catalog:
            product = CertIstProduct.from_xml_node(asset_catalog)
            product.save()

    """ Insert CERT-IST alerts into the database. """
    def insert_alerts(self):
        print("Fetching CERT-IST products from the database")
        products = CertIstProduct.objects.all()

        print("Fetching CVEs from the database")
        opencves = Cve.objects.all()

        files = CertIstAlert.get_all_alerts_files()
        print(f"Found {self.blue(len(files))} alerts, adding them in database")

        for file in files:
            alert = CertIstAlert.read_alert_from_file(file)
            alert.save()
            alert = CertIstAlert.read_alert_many_to_many_fields(file, alert, opencves, products)
            alert.save()

    """ Insert CERT-IST advisories into the database. """
    def insert_advisories(self):

        print("Fetching CERT-IST products from the database")
        products = CertIstProduct.objects.all()

        print("Fetching CVEs from the database")
        opencves = Cve.objects.all()

        files = CertIstAdvisory.get_all_advisories_files()
        print(f"Found {self.blue(len(files))} advisories, adding them in database")

        for file in files:
            advisory = CertIstAdvisory.read_advisory_from_file(file)
            advisory.save()
            advisory = CertIstAdvisory.read_advisory_many_to_many_fields(file, advisory, opencves, products)
            advisory.save()


    """ Handle the command. """
    def handle(self, *args, **options):
        if not self.kb_repo_exist():
            self.error("The CERT-IST repository has to be cloned first")
            return
        
        self.info(f"Cleaning CERT-IST data first")
        CertIstProduct.objects.all().delete()
        CertIstAlert.objects.all().delete()
        CertIstAdvisory.objects.all().delete()

        self.info(f"Parsing the CERT-IST products repository ({self.blue(self.CERTIST_PATH)})")
        self.insert_products()

        self.info(f"Parsing the CERT-IST alerts ({self.blue(self.CERTIST_PATH)})")
        self.insert_alerts()

        self.info(f"Parsing the CERT-IST advisories ({self.blue(self.CERTIST_PATH)})")
        self.insert_advisories()
