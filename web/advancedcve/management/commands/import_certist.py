import datetime
import glob
import pathlib
import xml.etree.ElementTree as ET

from django.conf import settings

from opencve.commands import BaseCommand
from advancedcve.models import CertIstAdvisory, CertIstAlert, CertIstProduct
from cves.models import Cve


class Command(BaseCommand):
    CERTIST_PATH = settings.CERTIST_REPO_PATH
    
    """ Check if the CERT-IST repository exists. """
    def kb_repo_exist(self):
        return pathlib.Path.exists(pathlib.Path(self.CERTIST_PATH))

    """ Insert CERT-IST products into the database. """
    def insert_products(self):
        products_path = pathlib.Path(self.CERTIST_PATH) / "products/products.xml"
        tree = ET.parse(products_path)
        root = tree.getroot()

        assets_catalog = root.findall(".//Asset_Catalog")
        print(f"Found {self.blue(len(assets_catalog))} products in the CERT-IST repository")

        for asset_catalog in assets_catalog:
            product = CertIstProduct()
            product.certist_id = asset_catalog.get('id')
            product.vendor = asset_catalog.find('Vendor').text
            product.product = asset_catalog.find('Product').text
            product.product_category = asset_catalog.find('Product').get("category")
            product.version = asset_catalog.find('Version').text
            product.created = datetime.datetime.strptime(asset_catalog.find('Creation_Date').text, '%Y-%m-%d').date()
            if(asset_catalog.find('Obsoleted') is not None):
                product.obsoleted = datetime.datetime.strptime(asset_catalog.find('Obsoleted').text, '%Y-%m-%d').date()
            product.monitoring_level = asset_catalog.find('Monitoring_Level').text

            cpes = []
            for cpe in asset_catalog.find('Cpe_List').findall(".//Cpe"):
                cpes.append(cpe.text)
            product.cpes = cpes 
            product.save()

    """ Retrieve the root information from the xml node. """
    def retrieve_root_information(self, object, root) :
        object.issuer = root.get("issuer")
        object.date = datetime.datetime.strptime(root.get("date"), '%Y-%m-%d').date()

    """ Retrieve the Id_Data information from the xml node. """
    def retrieve_id_data_information(self, object, root) :
        id_data = root.find("Id_Data")
        object.ref_number = id_data.find("ref_num").text
        titles = {}
        for title in id_data.find('title').findall(".//FreeText"):
            titles.update({title.get("{http://www.w3.org/XML/1998/namespace}lang"): title.text}) 
        object.titles = titles

    """ Retrieve the Description information from the xml node. """
    def retrieve_description_information(self, object, root) :
        descriptions_xml = root.find("Description").find("description")
        descriptions = {}
        for description in descriptions_xml.findall(".//FormattedText"):
            descriptions.update({description.get("{http://www.w3.org/XML/1998/namespace}lang"): ''.join(ET.tostring(e, encoding='unicode') for e in description)})
        object.descriptions = descriptions

    """ Retrieve the History information from the xml node. """
    def retrieve_history_information(self, object, root):
        history_data = root.find("History_Data").find("version_history")
        history = []
        for description in history_data.findall(".//change_descr"):
            change = {}
            change.update({"date": description.get("date")})
            change.update({"version": description.get("version")})
            change_descriptions = {}
            for change_description in description.findall(".//FreeText"):
                change_descriptions.update({change_description.get("{http://www.w3.org/XML/1998/namespace}lang"): change_description.text})
            change.update({"descriptions": change_descriptions})
            history.append(change)
        object.history = history

    """ Retrieve the Vulnerability Class information from the xml node. """
    def retrieve_vulnerability_class_information(self, object, root):
        vulnerability_classification = {}

        #Get Vulnerability Class information.
        vulnerability_class = root.find("Vulnerability_Class")
        vulnerability_classification.update({"confidence_level": vulnerability_class.find("confidence_level").text})
        vulnerability_classification.update({"attack_expertise": vulnerability_class.find("attack_expertise").text})
        vulnerability_classification.update({"attack_requirements": vulnerability_class.find("attack_requirements").text})
        vulnerability_classification.update({"risk": vulnerability_class.find("risk").text})
        impacts = []
        for impact in vulnerability_class.findall(".//impact"):
            impacts.append(impact.text)
        vulnerability_classification.update({"impacts": impacts})

        #Get Vulnerability Class 2 information.
        vulnerability_class2 = root.find("Vulnerability_Class_2")
        vulnerability_classification.update({"eispp_risk_version": vulnerability_class2.find("eispp_risk_version").text})
        vulnerability_classification.update({"public_exploit": vulnerability_class2.find("public_exploit").text})
        
        attack_level = vulnerability_class2.find("attack_level")
        if attack_level is not None:
            vulnerability_classification.update({"attack_level": attack_level.text})

        attack_seen = vulnerability_class2.find("attack_seen")
        if attack_seen is not None:
            vulnerability_classification.update({"attack_seen": attack_seen.text})

        object.vulnerability_class = vulnerability_classification

    """ Retrieve the Solutions information from the xml node. """
    def retrieve_solutions_information(self, object, root):
        #Get Solution information.
        solutions = []
        for sol_section in root.find("Solution").findall(".//sol_section"):
            solution = {}
            solution.update({"type": sol_section.get("sol_type")})
            sol_title = sol_section.find(".//sol_title")
            for freetext in sol_title.findall(".//FreeText"):
                title = {"title": freetext.text}
                solution.update({freetext.get("{http://www.w3.org/XML/1998/namespace}lang"): title})
            
            sol_descr = sol_section.find(".//sol_descr")
            for formatted_text in sol_descr.findall(".//FormattedText"):
                temp = solution.get(formatted_text.get("{http://www.w3.org/XML/1998/namespace}lang"))
                temp.update({"description": ''.join(ET.tostring(e, encoding='unicode') for e in formatted_text)})
                solution.update({formatted_text.get("{http://www.w3.org/XML/1998/namespace}lang"): temp})

            references = {}
            for reference in sol_section.findall(".//reference"):
                temp_reference = {}
                ref_title = reference.find(".//ref_title")
                for freetext in ref_title.findall(".//FreeText"):
                    title = {"title": freetext.text}
                    temp_reference.update({freetext.get("{http://www.w3.org/XML/1998/namespace}lang"): title})
                
                for uri in reference.findall(".//uri"):
                    temp = temp_reference.get(uri.get("{http://www.w3.org/XML/1998/namespace}lang"))
                    temp.update({"uri": uri.text})
                    temp_reference.update({uri.get("{http://www.w3.org/XML/1998/namespace}lang"): temp})

                ref_type = reference.get("ref_type")
                issuer = reference.get("issuer")
                ref_num = reference.get("ref_num")

                for key in temp_reference.keys():
                    temp = references.get(key)
                    if temp is None :
                        temp = []
                    temp_reference.get(key).update({"ref_type": ref_type})
                    temp_reference.get(key).update({"issuer": issuer})
                    temp_reference.get(key).update({"ref_num": ref_num})
                    temp.append(temp_reference.get(key))
                    references.update({key: temp})

            for key in references.keys():
                temp = solution.get(key)
                temp.update({"references": references.get(key)})
                solution.update({key: temp})
                solutions.append(solution)
        object.solutions = solutions

    """ Retrieve the Additional Resources information from the xml node. """
    def retrieve_additional_resources_information(self, object, root):
        additional_resources = root.find("Additional_Resources")
        references = []
        for resource in additional_resources.findall(".//reference"):
            reference = {}
            for uri in resource.findall(".//uri"):
                temp_uri = {"uri": uri.text}
                reference.update({uri.get("{http://www.w3.org/XML/1998/namespace}lang"): temp_uri})
            title = resource.find(".//ref_title")
            for freetext in title.findall(".//FreeText"):
                temp_ref = reference.get(freetext.get("{http://www.w3.org/XML/1998/namespace}lang"))
                if temp_ref is None:
                    temp_ref = {}
                temp_ref.update({"title": freetext.text})
                reference.update({freetext.get("{http://www.w3.org/XML/1998/namespace}lang"): temp_ref})
            references.append(reference)
        object.references = references

    """ Retrieve the Vulnerability Score information from the xml node. """
    def retrieve_vulnerability_score_information(self, object, root):
        vulnerability_score = root.find("Vulnerability_Score")
        if vulnerability_score is not None:
            cvss_xml = vulnerability_score.find("CVSS")
            if  cvss_xml is not None:
                cvss = {}
                cvss.update({"version": cvss_xml.get("version")})
                cvss.update({"cvss_issuer": cvss_xml.find("cvss_issuer").text})
                cvss.update({"cvss_vuln_id": cvss_xml.find("cvss_vuln_id").text})
                cvss.update({"cvss_base_score": cvss_xml.find("cvss_base_score").text})
                cvss.update({"cvss_base_vector": cvss_xml.find("cvss_base_vector").text})
                cvss.update({"cvss_temporal_score": cvss_xml.find("cvss_temporal_score").text})
                cvss.update({"cvss_temporal_vector": cvss_xml.find("cvss_temporal_vector").text})
                object.cvss = cvss

    """ Retrieve the Vulnerability ID information from the xml node. """
    def retrieve_vulnerability_id_information(self, object, root, opencves):
        vulnerability_id = root.find("Vulnerability_ID")
        cves = []
        for reference in vulnerability_id.findall(".//reference"):
            cve = opencves.filter(cve_id=reference.get("ref_num")).first()
            if cve is not None:
                cves.append(cve)
        object.cves.set(cves)

    def retrieve_system_information(self, object, root, products):
        system_information_xml = root.find("System_Information")
        system_information = {}

        affected_platforms = {}
        for platform in system_information_xml.find("affected_platform").findall(".//FormattedText"):
            affected_platforms.update({platform.get("{http://www.w3.org/XML/1998/namespace}lang"): ''.join(ET.tostring(e, encoding='unicode') for e in platform)})
        system_information.update({"affected_platform": affected_platforms})

        affected_softwares = {}
        for platform in system_information_xml.find("affected_software").findall(".//FormattedText"):
            affected_softwares.update({platform.get("{http://www.w3.org/XML/1998/namespace}lang"): ''.join(ET.tostring(e, encoding='unicode') for e in platform)})
        system_information.update({"affected_softwares": affected_softwares})
        object.system_information = system_information

        affected_products = []
        for product in system_information_xml.find("system_id_list").findall(".//Asset_Catalog"):
            affected_product = products.filter(certist_id=product.get("id")).first()
            if affected_product is not None:
                affected_products.append(affected_product)
            else:
                print(f"Product with id {product.get('id')} not found in the database")
        object.affected_products.set(affected_products)

    """ Insert CERT-IST alerts into the database. """
    def insert_alerts(self):
        print("Fetching CERT-IST products from the database")
        products = CertIstProduct.objects.all()

        print("Fetching CVEs from the database")
        opencves = Cve.objects.all()

        files = glob.glob(self.CERTIST_PATH + "/alerts/**/*.xml", recursive=True)
        print(f"Found {self.blue(len(files))} alerts, adding them in database")

        for file in files:
            tree = ET.parse(file)
            root = tree.getroot()

            alert = CertIstAlert()
            self.retrieve_root_information(alert, root)
            self.retrieve_id_data_information(alert, root)
            self.retrieve_description_information(alert, root)
            self.retrieve_history_information(alert, root)
            self.retrieve_vulnerability_class_information(alert, root)
            self.retrieve_solutions_information(alert, root)
            self.retrieve_additional_resources_information(alert, root)
            self.retrieve_vulnerability_score_information(alert, root)

            #Save before adding the ManyToMany fields.
            alert.save()
            
            self.retrieve_vulnerability_id_information(alert, root, opencves)
            self.retrieve_system_information(alert, root, products)
            alert.save()


    """ Insert CERT-IST advisories into the database. """
    def insert_advisories(self):

        print("Fetching CERT-IST products from the database")
        products = CertIstProduct.objects.all()

        print("Fetching CVEs from the database")
        opencves = Cve.objects.all()

        files = glob.glob(self.CERTIST_PATH + "/advisories/**/*.xml", recursive=True)
        print(f"Found {self.blue(len(files))} advisories, adding them in database")

        for file in files:
            tree = ET.parse(file)
            root = tree.getroot()

            advisory = CertIstAdvisory()
            self.retrieve_root_information(advisory, root)
            self.retrieve_id_data_information(advisory, root)
            self.retrieve_description_information(advisory, root)
            self.retrieve_history_information(advisory, root)
            self.retrieve_vulnerability_class_information(advisory, root)
            self.retrieve_solutions_information(advisory, root)
            self.retrieve_additional_resources_information(advisory, root)
            self.retrieve_vulnerability_score_information(advisory, root)

            #Save before adding the ManyToMany fields.
            advisory.save()
            
            self.retrieve_vulnerability_id_information(advisory, root, opencves)
            self.retrieve_system_information(advisory, root, products)
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
