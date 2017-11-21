# Import stuff
from django.conf.urls import url
from django.views.generic import RedirectView
from django.views.generic import TemplateView, ListView, DetailView
from policy_mgmnt.models import Firewall, Policies
from . import views

#Redirect to index function in views.py
urlpatterns = [
 url(r'^policy_mgmnt/', views.home, name='policy_mgmnt'),
 url(r'^$', views.home, name='policy_mgmnt'),
 url(r'^submit', views.submit),
 url(r'^modify_policy', views.modify_policy),
 url(r'^(?P<pk>\d+)-(?P<slug>[-\w]+)/$', DetailView.as_view(
    context_object_name='policy',
    template_name='policy.html',
 ), name="policy"),
#  url(r'^modify_policy_chosen/$', views.modify_policy_chosen),
 url(r'^policyUpdate/', views.policyUpdate),
 
 url(r'^DisplayPolicyToUpdate', views.DisplayPolicyToUpdate),
]

 
urlpatterns += [
    url(r'^$', RedirectView.as_view(url='/', permanent=True))
    
    
]