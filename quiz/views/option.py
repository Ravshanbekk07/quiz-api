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



class OptionView(View):
    def get(self,request,quiz_id, question_id,pk=None):
        headers = request.headers
        authozation = headers.get('Authorization')
        if not authozation:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        else:
            authozation = authozation.split()
            if authozation[0] != 'Basic':
                return JsonResponse({'error': 'Unauthorized'}, status=401)
            decoded_auth_header = b64decode(authozation[1]).decode('utf-8')
            username, password = decoded_auth_header.split(':')
            user = authenticate(username=username, password=password)
            if not user:
                return JsonResponse({'error': 'Unauthorized'}, status=401)
          
            else:
                try:
                    quiz = Quiz.objects.get(id=quiz_id)
                except Quiz.DoesNotExist:
                    return JsonResponse({"error":'Quiz not found'})
                try:
                    question = Question.objects.get(quiz=quiz, id=question_id)
                except Question.DoesNotExist:
                     return JsonResponse({"error":'Question not found'})
                    
                if pk is None:
                    options = Option.objects.filter(question=question).all()
                    option_dict = [model_to_dict(option) for option in options]
                    return JsonResponse(option_dict, safe=False)
                else:
                    try:
                        quiz = Quiz.objects.get(id=quiz_id)
                        question = Question.objects.get(quiz=quiz,id = question_id)
                        option = Option.objects.get(question=question,pk=pk)
                        option_dict = model_to_dict(option,fields=['id','question',"content"])
                        return JsonResponse(option_dict)
                    except Quiz.DoesNotExist:
                        return JsonResponse({"error":"Quiz not found"},status=404)
                    except Question.DoesNotExist:
                        return JsonResponse({"error":"Question not found"},status=404)
                    except Option.DoesNotExist:
                        return JsonResponse({"error":"Option not found"},status=404)

    def post(self,request,quiz_id,question_id):
        headers = request.headers
        authorization = headers.get("Authorization")
        if not authorization:
            return JsonResponse({'error':'unauthorized'},status= 401)
        else:
            authorization = authorization.split()
            if authorization[0]!="Basic":
                return JsonResponse({'error':'unauthorized'},status=401)
            
            decode_auth = b64decode(authorization[1]).decode('utf-8')
            username,password = decode_auth.split(":")
            user = authenticate(username=username,password=password)

            if not user:
                return JsonResponse({'error':'unauthorized'},status =401)
            elif not user.is_superuser:
                return JsonResponse({'error':'forbidden'},status =403)
            else:
                try:
                    quiz = Quiz.objects.get(id=quiz_id)
                except Quiz.DoesNotExist:
                    return JsonResponse({"error":'Quiz not found'})
                try:
                    question = Question.objects.get(quiz=quiz, id=question_id)
                except Question.DoesNotExist:
                     return JsonResponse({"error":'Question not found'})
                quiz = Quiz.objects.get(id=quiz_id)
                question = Question.objects.get(quiz=quiz,id = question_id)
                data = json.loads(request.body.decode('utf-8'))
                option = Option.objects.create(
                        question=question,
                        
                        content = data.get('content'),
                        is_correct=data.get('is_correct'))
                option.save()
                return JsonResponse(model_to_dict(option),status = 201)
               

    def put(self,request,quiz_id,question_id,pk):
        headers = request.headers
        authorization = headers.get('Authorization')
        if not authorization:
            return JsonResponse({'error':'unauthorized'},status=401)
        else:
            authorization = authorization.split()
            if authorization[0]!='Basic':
                return JsonResponse({'error':'unauthorized'},status=401)
            decode_auth = b64decode(authorization[1]).decode('utf-8')
            username,password = decode_auth.split(":")
            user = authenticate(username=username,password=password)

            if not user:
                return JsonResponse({'error':'unauthorized'},status=401)
            elif not user.is_superuser:
                return JsonResponse({'error':'forbidden'},status=403)
            else:
                try:
                    quiz = Quiz.objects.get(id=quiz_id)
                except Quiz.DoesNotExist:
                    return JsonResponse({"error":'Quiz not found'})
                try:
                    question = Question.objects.get(quiz=quiz, id=question_id)
                except Question.DoesNotExist:
                     return JsonResponse({"error":'Question not found'})
                try:
                    option = Option.objects.get(question=question,pk=pk)
                except Option.DoesNotExist:
                    return JsonResponse({"error":'Option not found'})
                data = json.loads(request.body.decode('utf-8'))

                option.question =question
                option.content = data.get('content',option.content)
                option.is_correct = data.get('is_correct',option.is_correct)
                option.save()
                return JsonResponse(model_to_dict(option),status = 201)

    def delete(self,request,quiz_id,question_id,pk):
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
                        quiz = Quiz.objects.get(id=quiz_id)
                    except Quiz.DoesNotExist:
                        return JsonResponse({"error":'Quiz not found'})
                    try:
                        question = Question.objects.get(quiz=quiz, id=question_id)
                    except Question.DoesNotExist:
                        return JsonResponse({"error":'Question not found'})
                    try:
                        option = Option.objects.get(question=question,pk=pk)
                    except Option.DoesNotExist:
                        return JsonResponse({"error":'Option not found'})
                    
                    option.delete()
                    return JsonResponse({'status':'ok'})