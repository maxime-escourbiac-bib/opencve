from django.db import models

from django.contrib.postgres.indexes import GinIndex, OpClass
from django.db import models
from django.db.models.functions import Upper

from cves.models import Cve


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