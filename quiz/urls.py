from django.urls import path
from . import views

urlpatterns = [
    path('quiz/', views.QuizList.as_view()),
    path('quiz/<int:pk>/', views.QuizList.as_view()),

    path('quiz/<int:quiz_id>/question/',views.Questionview.as_view()),
    path('quiz/<int:quiz_id>/question/<int:pk>/',views.Questionview.as_view()),

    path('quiz/<int:quiz_id>/question/<int:question_id>/option/',views.OptionView.as_view()),
    path('quiz/<int:quiz_id>/question/<int:question_id>/option/<int:pk>/',views.OptionView.as_view()),
    
    path('quiz/<int:quiz_id>/take/',views.TakeView.as_view()),
    path('quiz/<int:quiz_id>/take/<int:pk>/',views.TakeView.as_view()),
    

    path('quiz/take/<int:take_id>/answer/',views.ResponseView.as_view()),
]