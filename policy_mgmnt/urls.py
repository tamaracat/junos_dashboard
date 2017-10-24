# Import stuff
from django.conf.urls import url
from django.views.generic import RedirectView
from . import views

#Redirect to index function in views.py
urlpatterns = [
 url(r'^policy_mgmnt/', views.home, name='policy_mgmnt'),
 url(r'^$', views.home, name='policy_mgmnt'),
 url(r'^submit', views.submit),
 url(r'^modify_policy', views.modify_policy),
 url(r'^modify_policy_result', views.modify_policy_result),
 url(r'^home', views.home)
]

urlpatterns += [
    url(r'^$', RedirectView.as_view(url='/policy_mgmnt/', permanent=True))
    
]