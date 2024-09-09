from django.urls import re_path
from advancedcve import views


urlpatterns = [
    re_path(r'^$', views.index)
]