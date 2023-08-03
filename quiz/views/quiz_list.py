from django.http import HttpRequest, JsonResponse
from django.views import View
from quiz.models import (
    Quiz,
    
    Option,
    Take,
    Response,
    Question
)
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.forms.models import model_to_dict
from base64 import b64decode
import json


class QuizList(View):
    def get(self, request: HttpRequest,pk=None) -> JsonResponse:
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
                if pk is None:
                    # get all the quizzes
                    quizzes = Quiz.objects.all()
                    # convert quizzes to list of dictionaries
                    quizzes = [model_to_dict(quiz) for quiz in quizzes]
                    # return quizzes as json response
                    return JsonResponse(quizzes, safe=False)
                else:
                    try:
                        quiz = Quiz.objects.get(id=pk)
                        quiz_dict = model_to_dict(quiz,fields=['id','name',"description"])
                        return JsonResponse(quiz_dict)
                    except User.DoesNotExist:
                        return JsonResponse({'error':'user not found'})
                    except Quiz.DoesNotExist:
                        return JsonResponse({"error":"quiz not found"},status=404)

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
                if name is None:
                     return JsonResponse({"error": "name is reqeuired."})
                # get the description from body
                description = body.get('description')
                if description is None:
                     return JsonResponse({"error": "description is reqeuired."})
                # create a quiz
                quiz = Quiz.objects.create(
                    name=name,
                    description=description
                )
                # convert quiz to dictionary
                quiz = model_to_dict(quiz)
                # return quiz as json response
                return JsonResponse(quiz, status=201)
            
    def put(self,request,pk):
        headers = request.headers
        authorization = headers.get("Authorization")
        if not authorization:
            return JsonResponse({'error':"Unauthorized"},status=401)
        else:
            authorization = authorization.split()
            if authorization[0]!='Basic':
                return JsonResponse({'error':'unauthorized'},status=401)
            decode_authorization =b64decode(authorization[1]).decode('utf-8')
            username,password = decode_authorization.split(':')
            user = authenticate(username=username,password=password)

            if not user:
                return JsonResponse({'error':'unauthorized'},status =401)
            elif not user.is_superuser:
                return JsonResponse({'error':'forbidden'},status=403)
            else:
                data = json.loads(request.body.decode('utf-8'))
                quiz = Quiz.objects.get(pk=pk)
                quiz.name = data.get('name',quiz.name)
                quiz.description = data.get('description',quiz.description)
                quiz.save()
                return JsonResponse(model_to_dict(quiz),status=201)
    def delete(self,request,pk=int):
                headers = request.headers
                authorization = headers.get('Authorization')
                if not authorization:
                    return JsonResponse({'error':'unauthorized'},status =401)
                else:
                    authorization =authorization.split()
                if authorization[0]!='Basic':
                    return JsonResponse({'error':'unauthorized'},status =401)
    

                username,password = b64decode(authorization[1]).decode('utf-8').split(':')
                user  = authenticate(username=username,password= password)
                if not user:
                    return JsonResponse({'error':'unauthorized'},status =401)
                elif not user.is_superuser:
                    return JsonResponse({'error':'forbidden'},status=403)
                else:
                    try:
                        quiz = Quiz.objects.get(pk=pk)
                        quiz.delete()
                        return JsonResponse({'status':'ok'})
                    except Quiz.DoesNotExist:
                         return JsonResponse({"error":"Quiz not found"})