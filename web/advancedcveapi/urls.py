from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r'^hello/$', views.hello_world),

]