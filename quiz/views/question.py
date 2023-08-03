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

                
class Questionview(View):
    def get(self, request: HttpRequest,quiz_id,pk=None) -> JsonResponse:
        headers = request.headers
        auth_header = headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        else:
            auth_header = auth_header.split()
            if auth_header[0] != 'Basic':
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            decoded_auth_header = b64decode(auth_header[1]).decode('utf-8')
            username, password = decoded_auth_header.split(':')
            user = authenticate(username=username, password=password)
            if not user:
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            if not quiz_id:
                    return JsonResponse({"error":'quiz id is required'})
            else:
                try:
                    quiz = Quiz.objects.get(id=quiz_id)
                except Quiz.DoesNotExist:
                    
                    return JsonResponse({"error": "quiz not found."})
                if pk is None:
                    # questions=Question.get(quiz_id=quiz)
                    questions = Question.objects.filter(quiz=quiz).all()
                    questions_dic = [model_to_dict(question) for question in questions]
                    return JsonResponse(questions_dic, safe=False)
                else:
                    try:
                        question = Question.objects.get(quiz=quiz, id=pk)
                        question_dict = model_to_dict(question)
                        return JsonResponse(question_dict)
                    except Quiz.DoesNotExist:
                        return JsonResponse({'error':'quiz not found'},status=404)
                    except Question.DoesNotExist:
                         return JsonResponse({'error':'question not found'},status =404)
    def post(self, reqeust: HttpRequest,quiz_id) -> JsonResponse:
        headers = reqeust.headers
        auth_header = headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        else:
            auth_header = auth_header.split()
            if auth_header[0] != 'Basic':
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            decoded_auth_header = b64decode(auth_header[1]).decode('utf-8')
            username, password = decoded_auth_header.split(':')
            user = authenticate(username=username, password=password)
            if not user:
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            elif not user.is_superuser:
                return JsonResponse({'error': 'Forbidden'}, status=403)
            else:
                try:
                    quiz = Quiz.objects.get(id=quiz_id)
                except Quiz.DoesNotExist:
                     return JsonResponse({"error": "quiz not found."})
                body = reqeust.body
                body = body.decode('utf-8')
                body = json.loads(body)
                
                
                content = body.get('content')
                
                if content is None:
                     return JsonResponse({"error": "content is reqeuired."})
                # question = Question.objects.get(quiz=quiz)
                # print(question)

                question = Question.objects.create(
                    quiz=quiz,
                    content = content
                )
                question.save()
                return JsonResponse(model_to_dict(question), status=201)
            
    def put(self, reqeust: HttpRequest,quiz_id,pk) -> JsonResponse:
        headers = reqeust.headers
        auth_header = headers.get('Authorization')
        if not auth_header:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        else:
            auth_header = auth_header.split()
            if auth_header[0] != 'Basic':
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            decoded_auth_header = b64decode(auth_header[1]).decode('utf-8')
            username, password = decoded_auth_header.split(':')
            user = authenticate(username=username, password=password)
            if not user:
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            elif not user.is_superuser:
                return JsonResponse({'error': 'Forbidden'}, status=403)
            else:
                try:
                    quiz = Quiz.objects.get(id=quiz_id)
                except Quiz.DoesNotExist:
                     return JsonResponse({"error": "quiz not found."})
              
                body = reqeust.body
                body = body.decode('utf-8')
                body = json.loads(body)
                
                
                content = body.get('content')
                
                if content is None:
                     return JsonResponse({"error": "content is reqeuired."})
                question = Question.objects.get(quiz=quiz,pk=pk)
                
               
                quiz=quiz,
                question.content = body.get("content",question.content)
                
                question.save()
                return JsonResponse(model_to_dict(question), status=201)
    def delete(self,request,quiz_id,pk):
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
                if not pk:
                     return JsonResponse({'error':'id is required'})
                else:
                    try:
                        try:
                            quiz = Quiz.objects.get(id=quiz_id)
                        except Quiz.DoesNotExist:
                            return JsonResponse({"error": "quiz not found."})
                        
                        

                        question = Question.objects.get(quiz=quiz,id=pk)
                        question.delete()
                        return JsonResponse({'status':'ok'})
                    except Question.DoesNotExist:
                         return JsonResponse({"error":"Quiz not found"})