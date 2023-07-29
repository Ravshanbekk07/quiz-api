from django.urls import path
from . import views

urlpatterns = [
    path('quiz/', views.QuizList.as_view()),
]