from django.http import HttpRequest, JsonResponse
from django.views import View
from .models import (
    Quiz,
    Question,
    Option,
    Take,
    Response
)
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.forms.models import model_to_dict
from base64 import b64decode
import json


class QuizList(View):
    def get(self, request: HttpRequest) -> JsonResponse:
        # get headers from request
        headers = request.headers
        # get authorization header
        auth_header = headers.get('Authorization')
        # if authorization header is not present
        if not auth_header:
            # return 401 status code
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        # if authorization header is present
        else:
            # split the authorization header
            auth_header = auth_header.split()
            # if authorization header is not basic
            if auth_header[0] != 'Basic':
                # return 401 status code
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            # decode the authorization header
            decoded_auth_header = b64decode(auth_header[1]).decode('utf-8')
            # split the authorization header
            username, password = decoded_auth_header.split(':')
            # authenticate the user
            user = authenticate(username=username, password=password)
            # if user is not authenticated
            if not user:
                # return 401 status code
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            # if user is authenticated
            else:
                # get all the quizzes
                quizzes = Quiz.objects.all()
                # convert quizzes to list of dictionaries
                quizzes = [model_to_dict(quiz) for quiz in quizzes]
                # return quizzes as json response
                return JsonResponse(quizzes, safe=False)

    def post(self, reqeust: HttpRequest) -> JsonResponse:
        # get headers from request
        headers = reqeust.headers
        # get authorization header
        auth_header = headers.get('Authorization')
        # if authorization header is not present
        if not auth_header:
            # return 401 status code
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        # if authorization header is present
        else:
            # split the authorization header
            auth_header = auth_header.split()
            # if authorization header is not basic
            if auth_header[0] != 'Basic':
                # return 401 status code
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            # decode the authorization header
            decoded_auth_header = b64decode(auth_header[1]).decode('utf-8')
            # split the authorization header
            username, password = decoded_auth_header.split(':')
            # authenticate the user
            user = authenticate(username=username, password=password)
            # if user is not authenticated
            if not user:
                # return 401 status code
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            # if user is nor superuser
            elif not user.is_superuser:
                # return 403 status code
                return JsonResponse({'error': 'Forbidden'}, status=403)
            # if user is authenticated
            else:
                # get the body from request
                body = reqeust.body
                # decode the body
                body = body.decode('utf-8')
                # convert the body to dictionary
                body = json.loads(body)
                # get the name from body
                name = body.get('name')
                # get the description from body
                description = body.get('description')
                # create a quiz
                quiz = Quiz.objects.create(
                    name=name,
                    description=description
                )
                # convert quiz to dictionary
                quiz = model_to_dict(quiz)
                # return quiz as json response
                return JsonResponse(quiz, status=201)

