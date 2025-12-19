"""
URLs de la aplicación crypto_app.
"""

from django.urls import path
from . import views

app_name = 'crypto_app'

urlpatterns = [
    # Vistas HTML
    path('', views.index, name='index'),
    path('algorithms/', views.algorithms_view, name='algorithms'),
    path('authentication/', views.authentication_view, name='authentication'),
    path('attacks/', views.attacks_view, name='attacks'),
    
    # API - Algoritmos
    path('api/caesar/', views.api_caesar, name='api_caesar'),
    path('api/lfsr/', views.api_lfsr, name='api_lfsr'),
    path('api/aes/', views.api_aes, name='api_aes'),
    path('api/custom-symmetric/', views.api_custom_symmetric, name='api_custom_symmetric'),
    path('api/custom-asymmetric/', views.api_custom_asymmetric, name='api_custom_asymmetric'),
    
    # API - Autenticación
    path('api/hmac/', views.api_hmac, name='api_hmac'),
    path('api/signature/', views.api_signature, name='api_signature'),
    path('api/origin-verification/', views.api_origin_verification, name='api_origin_verification'),
    
    # API - Ataques
    path('api/brute-force/', views.api_brute_force, name='api_brute_force'),
    path('api/mitm/', views.api_mitm, name='api_mitm'),
]
