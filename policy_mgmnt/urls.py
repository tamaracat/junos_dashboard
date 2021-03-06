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
    url(r'^modify_policy', views.modify_policy, name='modify_policy'),
    url(r'^get_facts', views.get_facts, name='get_facts'),
    url(r'^(?P<pk>\d+)-(?P<slug>[-\w]+)/$', DetailView.as_view(
        context_object_name='policy',
        template_name='policy.html',
        ), name="policy"),

    url(r'^policyUpdate/$', views.policyUpdate, name='policyUpdate'),
    # url(r'^DisplayPolicyToUpdate/(?P<policy_name>\d+)/$', views.DisplayPolicyToUpdate, name='DisplayPolicyToUpdate'),

    url(r'^products/$', views.products_view, name='products'),
]

urlpatterns += [
    url(r'^$', RedirectView.as_view(url='/', permanent=False))
]

 
