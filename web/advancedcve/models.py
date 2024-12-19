from cves.models import Cve
from django.conf import settings
from django.contrib.postgres.indexes import GinIndex, OpClass
from django.db import models
from django.db.models.functions import Upper

import datetime
import glob
import pathlib
import xml.etree.ElementTree as ET


"""CERT-IST product catalog model."""
class CertIstProduct(models.Model):
    id = models.AutoField(primary_key=True)
    certist_id = models.IntegerField()
    vendor = models.CharField(max_length=256)
    product = models.CharField(max_length=256)
    product_category = models.CharField(max_length=1024)
    version = models.CharField(max_length=256)
    created = models.DateField()
    obsoleted = models.DateField(null=True)
    monitoring_level = models.IntegerField()
    cpes = models.JSONField(default=list)

    class Meta:
        db_table = "advancedcve_certistproducts"
        indexes = [
            GinIndex(
                OpClass(Upper("vendor"), name="gin_trgm_ops"),
                name="ix_istproducts_vendor",
            ),
            GinIndex(
                OpClass(Upper("product"), name="gin_trgm_ops"),
                name="ix_istproducts_product",
            ),
            GinIndex(
                OpClass(Upper("product_category"), name="gin_trgm_ops"),
                name="ix_istproducts_product_cat",
            ),
            GinIndex(
                OpClass(Upper("version"), name="gin_trgm_ops"),
                name="ix_istproducts_version",
            ),
        ]
        
    def __str__(self):
        return f"{self.vendor}-{self.product}-{self.version}"
    
    """ Get all products from CERTIST repo."""
    def get_all_products_xml_node(products_path=pathlib.Path(settings.CERTIST_REPO_PATH) / "products/products.xml"):
        tree = ET.parse(products_path)
        root = tree.getroot()
        return root.findall(".//Asset_Catalog")

    """ Read product from xml node."""
    def from_xml_node(xml_node):
        product = CertIstProduct()
        product.certist_id = xml_node.get('id')
        product.vendor = xml_node.find('Vendor').text
        product.product = xml_node.find('Product').text
        product.product_category = xml_node.find('Product').get("category")
        product.version = xml_node.find('Version').text
        product.created = datetime.datetime.strptime(xml_node.find('Creation_Date').text, '%Y-%m-%d').date()
        if(xml_node.find('Obsoleted') is not None):
            product.obsoleted = datetime.datetime.strptime(xml_node.find('Obsoleted').text, '%Y-%m-%d').date()
        product.monitoring_level = xml_node.find('Monitoring_Level').text

        cpes = []
        for cpe in xml_node.find('Cpe_List').findall(".//Cpe"):
            cpes.append(cpe.text)
        product.cpes = cpes 
        return product
    

    
class CertIstCommon(models.Model):
    id = models.AutoField(primary_key=True)
    ref_number = models.CharField(max_length=256)
    issuer = models.CharField(max_length=256)
    date = models.DateField()
    titles = models.JSONField(default=dict)
    descriptions = models.JSONField(default=dict)
    history = models.JSONField(default=list)
    vulnerability_class = models.JSONField(default=dict)
    system_information = models.JSONField(default=dict)
    affected_products = models.ManyToManyField(CertIstProduct)
    cvss = models.JSONField(default=dict)
    references = models.JSONField(default=list)
    cves = models.ManyToManyField(Cve)
    solutions = models.JSONField(default=list)

    class Meta:
        abstract = True

    def __str__(self):
        return self.ref_number
    
    """ Retrieve the root information from the xml node. """
    def retrieve_root_information(object, root) :
        object.issuer = root.get("issuer")
        object.date = datetime.datetime.strptime(root.get("date"), '%Y-%m-%d').date()

    """ Retrieve the Id_Data information from the xml node. """
    def retrieve_id_data_information(object, root) :
        id_data = root.find("Id_Data")
        object.ref_number = id_data.find("ref_num").text
        titles = {}
        for title in id_data.find('title').findall(".//FreeText"):
            titles.update({title.get("{http://www.w3.org/XML/1998/namespace}lang"): title.text}) 
        object.titles = titles

    """ Retrieve the Description information from the xml node. """
    def retrieve_description_information(object, root) :
        descriptions_xml = root.find("Description").find("description")
        descriptions = {}
        for description in descriptions_xml.findall(".//FormattedText"):
            descriptions.update({description.get("{http://www.w3.org/XML/1998/namespace}lang"): ''.join(ET.tostring(e, encoding='unicode') for e in description)})
        object.descriptions = descriptions

    """ Retrieve the History information from the xml node. """
    def retrieve_history_information(object, root):
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
    def retrieve_vulnerability_class_information(object, root):
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
    def retrieve_solutions_information(object, root):
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
    def retrieve_additional_resources_information(object, root):
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
    def retrieve_vulnerability_score_information(object, root):
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
    def retrieve_vulnerability_id_information(object, root, opencves):
        vulnerability_id = root.find("Vulnerability_ID")
        cves = []
        for reference in vulnerability_id.findall(".//reference"):
            cve = opencves.filter(cve_id=reference.get("ref_num")).first()
            if cve is not None:
                cves.append(cve)
        object.cves.set(cves)

    """ Retrieve the System Information from the xml node. """
    def retrieve_system_information(object, root, products):
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

"""CERT-IST alert model."""
class CertIstAlert(CertIstCommon):

    class Meta:
        db_table = "advancedcve_certistalerts"
        indexes = [
            GinIndex(
                OpClass(Upper("ref_number"), name="gin_trgm_ops"),
                name="ix_istalert_ref_number",
            ),
            GinIndex(name="ix_istalerts_titles", fields=["titles"]),
            GinIndex(name="ix_istalerts_descriptions", fields=["descriptions"]),
            GinIndex(name="ix_istalerts_history", fields=["history"]),
            GinIndex(name="ix_istalerts_system_info", fields=["system_information"]),
            GinIndex(name="ix_istalerts_references", fields=["references"]),
            GinIndex(name="ix_istalerts_solutions", fields=["solutions"]),
        ]
        
    def __str__(self):
        return self.ref_number
    
    """ Get all alerts from CERTIST repo."""
    def get_all_alerts_files():
        return glob.glob(settings.CERTIST_REPO_PATH + "/alerts/**/*.xml", recursive=True)
    
    """ Read alert from file."""
    def read_alert_from_file(file):
        tree = ET.parse(file)
        root = tree.getroot()
        alert = CertIstAlert()
        CertIstCommon.retrieve_root_information(alert, root)
        CertIstCommon.retrieve_id_data_information(alert, root)
        CertIstCommon.retrieve_description_information(alert, root)
        CertIstCommon.retrieve_history_information(alert, root)
        CertIstCommon.retrieve_vulnerability_class_information(alert, root)
        CertIstCommon.retrieve_solutions_information(alert, root)
        CertIstCommon.retrieve_additional_resources_information(alert, root)
        CertIstCommon.retrieve_vulnerability_score_information(alert, root)
        return alert
    
    """ Read alert many to many fields."""
    def read_alert_many_to_many_fields(file, alert, opencves, products):
        tree = ET.parse(file)
        root = tree.getroot()
        CertIstCommon.retrieve_vulnerability_id_information(alert, root, opencves)
        CertIstCommon.retrieve_system_information(alert, root, products)
        return alert
    
"""CERT-IST advisory model."""
class CertIstAdvisory(CertIstCommon):

    class Meta:
        db_table = "advancedcve_certistadvisories"
        indexes = [
            GinIndex(
                OpClass(Upper("ref_number"), name="gin_trgm_ops"),
                name="ix_istadvisories_ref_number",
            ),
            GinIndex(name="ix_istadvisories_titles", fields=["titles"]),
            GinIndex(name="ix_istadvisories_descriptions", fields=["descriptions"]),
            GinIndex(name="ix_istadvisories_history", fields=["history"]),
            GinIndex(name="ix_istadvisories_system_info", fields=["system_information"]),
            GinIndex(name="ix_istadvisories_references", fields=["references"]),
            GinIndex(name="ix_istadvisories_solutions", fields=["solutions"]),
        ]
        
    def __str__(self):
        return self.ref_number
    
    """ Get all advisories from CERTIST repo."""
    def get_all_advisories_files():
        return glob.glob(settings.CERTIST_REPO_PATH + "/advisories/**/*.xml", recursive=True)
    
    """ Read advisory from file."""
    def read_advisory_from_file(file):
        tree = ET.parse(file)
        root = tree.getroot()
        advisory = CertIstAdvisory()
        CertIstCommon.retrieve_root_information(advisory, root)
        CertIstCommon.retrieve_id_data_information(advisory, root)
        CertIstCommon.retrieve_description_information(advisory, root)
        CertIstCommon.retrieve_history_information(advisory, root)
        CertIstCommon.retrieve_vulnerability_class_information(advisory, root)
        CertIstCommon.retrieve_solutions_information(advisory, root)
        CertIstCommon.retrieve_additional_resources_information(advisory, root)
        CertIstCommon.retrieve_vulnerability_score_information(advisory, root)
        return advisory
    
    """ Read advisory many to many fields."""
    def read_advisory_many_to_many_fields(file, advisory, opencves, products):
        tree = ET.parse(file)
        root = tree.getroot()
        CertIstCommon.retrieve_vulnerability_id_information(advisory, root, opencves)
        CertIstCommon.retrieve_system_information(advisory, root, products)
        return advisory