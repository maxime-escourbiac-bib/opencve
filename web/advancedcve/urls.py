from django.urls import re_path, include
from advancedcve import views


urlpatterns = [
    re_path(r'^$', views.index),
    re_path(r'^api/', include('advancedcveapi.urls')),
]