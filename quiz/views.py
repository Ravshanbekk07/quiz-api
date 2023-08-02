from django.http import HttpRequest, JsonResponse
from django.views import View
from .models import (
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
                     


class TakeView(View):
    def get(self,request,quiz_id,pk=None):
        headers = request.headers
        authorization = headers.get('Authorization')
        if not authorization:
            return JsonResponse({'error':'unauthorized'},status =401)
        else:
            authorization = authorization.split()
            if authorization[0]!='Basic':
                return JsonResponse({'error':'unauthorized'},status =401)
            
            decode_auth = b64decode(authorization[1]).decode('utf-8')
            username,password = decode_auth.split(":")
            user = authenticate(username=username,password=password)
            if not user:
               
                return JsonResponse({'error':'unauthorized'},status =401)
            if not user.is_superuser:
                return JsonResponse({'error':'forbidden'},status =401)
                 
            else:
                try:
                    quiz = Quiz.objects.get(id=quiz_id)
                except Quiz.DoesNotExist:
                     return JsonResponse({"error": "quiz not found."})
                
                
                if pk is None:
                    takes = Take.objects.filter(quiz=quiz).all()
                    take_dict = [model_to_dict(take,fields=['id','quiz',"user"]) for take in takes]
                    return JsonResponse(take_dict, safe=False)
                
            
                     
                else:
                    try:
                        
                        take = Take.objects.get(quiz=quiz,id=pk)
                        take_dict = model_to_dict(take,fields=['id','quiz',"user"])
                        return JsonResponse(take_dict)
                    
                    except Take.DoesNotExist:
                        return JsonResponse({"error":"Take not found"},status=404)
                    except Quiz.DoesNotExist:
                        return JsonResponse({"error":"Quiz not found"},status=404)
    def post(self,request,quiz_id):
        headers = request.headers
        authorization = headers.get('Authorization')
        if not authorization:
                return JsonResponse({'error':'unauthorized'},status =401)
        else:
            authorization =authorization.split()
            if authorization[0]!='Basic':
                return JsonResponse({'error':'unauthorized'},status =401)
            decode_auth = b64decode(authorization[1]).decode('utf-8')
            username,password = decode_auth.split(':')
            user = authenticate(username=username,password=password)
            if not user:
                return JsonResponse({'error':'unauthorized'},status =401)
            elif not user.is_superuser:
                return JsonResponse({'error':'forbidden'},status =401)
            else:
                
                
                try:
                    quiz = Quiz.objects.get(id=quiz_id)
                except Quiz.DoesNotExist:
                    return JsonResponse({'error':'quiz not found'})
                data = json.loads(request.body.decode('utf-8'))

                take = Take.objects.create(
                        quiz = quiz,
                        user = User.objects.get(id = data.get('user'))

                )
                take.save()
                return JsonResponse(model_to_dict(take),status = 201)
               
                
    def put(self,request,quiz_id,pk):
        headers = request.headers
        authorization = headers.get('Authorization')
        if not authorization:
            return JsonResponse({'error':'unauthorized'},status =401)
        else:
            authorization= authorization.split()
            if authorization[0]!='Basic':
                return JsonResponse({'error':'unauthorized'},status =401)
            decode_authorization = b64decode(authorization[1]).decode('utf-8')
            username,password = decode_authorization.split(':')
            user  = authenticate(username=username,password=password)
            if not user:
                return JsonResponse({'error':'unauthorized'},status =401)
            elif not user.is_superuser:
                return JsonResponse({'error':'unauthorized'},status =401)
            else:
             
                    data = json.loads(request.body.decode('utf-8'))
                    try:
                        quiz = Quiz.objects.get(id = quiz_id)
                    except Quiz.DoesNotExist:
                        return JsonResponse({'error':'quiz not found'},status =401)
                    try:
                        take = Take.objects.get(quiz=quiz,pk=pk)
                    except Take.DoesNotExist:
                        return JsonResponse({'error':'Take not found'},status =401)
                    quiz = quiz,
                    take.user = User.objects.get(id = data.get('user'))

                    
                    take.save()
                    return JsonResponse(model_to_dict(take),status = 201)
              
                

    def delete(self,request,quiz_id,pk):
                headers =  request.headers
                authorization = headers.get("Authorization")
                if not authorization:
                    return JsonResponse({'error':"Unauthorized"},status=401)
                else:     
                    authorization = authorization.split(' ')
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
                        quiz = Quiz.objects.get(id = quiz_id)
                    except Quiz.DoesNotExist:
                         return JsonResponse({"error":"Quiz not found"})
                    try:    
                        take = Take.objects.get(quiz =quiz,id=pk)
                        take.delete()
                        return JsonResponse({'status':'ok'})
                    except Take.DoesNotExist:
                        return JsonResponse({"error":"TAke not found"})
                    


class ResponseView(View):
    def get(self,request,pk=None):
        headers  = request.headers
        authorization = headers.get("Authorization")
        if not authorization:
                return JsonResponse({'error':'unauthorized'},status =401)
        else:
            authorization = authorization.split()
            if authorization[0] != 'Basic':
                    return JsonResponse({'error':'unauthorized'},status =401)
            decode_auth = b64decode(authorization[1]).decode('utf-8')
            username,password = decode_auth.split(":")
            user = authenticate(username=username,password=password)
            if not user:
                return JsonResponse({'error':'unauthorized'},status =401)
            else:
                if pk is None:
                    responses = Response.objects.all()
                    res_dic = [model_to_dict(response) for response in responses]
                    return JsonResponse(res_dic,safe=False)
                else:
                    try:
                        response = Response.objects.get(id=pk)
                        response_dic = model_to_dict(response)
                        return JsonResponse(response_dic)
                    except Response.DoesNotExist:
                        return JsonResponse({"error":"Response not found"},status=404)

    def post(self,request,take_id):
        headers  = request.headers
        authorization = headers.get("Authorization")
        if not authorization:
                return JsonResponse({'error':'unauthorized'},status =401)
        else:
            authorization = authorization.split()
            if authorization[0] != 'Basic':
                    return JsonResponse({'error':'unauthorized'},status =401)
            decode_auth = b64decode(authorization[1]).decode('utf-8')
            username,password = decode_auth.split(":")
            user = authenticate(username=username,password=password)
            if not user:
                return JsonResponse({'error':'unauthorized'},status =401)
            elif not user.is_superuser:
                return JsonResponse({'error':'unauthorized'},status =401)
            else:
                try:
                    take  = Take.objects.get(id = take_id)
                except Take.DoesNotExist:
                    return JsonResponse({'error':'Take not found'},status =401)
                    
                data = json.loads(request.body.decode('utf-8'))
                response = Response.objects.create(
                    take = take,
                    question = Question.objects.get(id = data.get('question')),
                    option = Option.objects.get(id = data.get('option')))
                response.save()
                return JsonResponse(model_to_dict(response))
                
               
            

    def put(self,request,pk):
        headers  = request.headers
        authorization = headers.get("Authorization")
        if not authorization:
                return JsonResponse({'error':'unauthorized'},status =401)
        else:
            authorization = authorization.split()
            if authorization[0] != 'Basic':
                    return JsonResponse({'error':'unauthorized'},status =401)
            decode_auth = b64decode(authorization[1]).decode('utf-8')
            username,password = decode_auth.split(":")
            user = authenticate(username=username,password=password)
            if not user:
                return JsonResponse({'error':'unauthorized'},status =401)
            elif not user.is_superuser:
                return JsonResponse({'error':'forbidden'},status =401)
            else:
                data = json.loads(request.body.decode('utf-8'))
                
                response = Response.objects.get(pk=pk)
                response.option = Option.objects.get(id = data.get('option'))
                response.save()
                return JsonResponse(model_to_dict(response),status = 201)

    def delete(self,request,pk):
                headers =  request.headers
                authorization = headers.get("Authorization")
                authorization = authorization.split(' ')
                username,password = b64decode(authorization[1]).decode('utf-8').split(':')
                user  = authenticate(username=username,password= password)
                if not user:
                    return JsonResponse({'error':'unauthorized'},status =401)
                elif not user.is_superuser:
                    return JsonResponse({'error':'forbidden'},status=403)
                else:
                    try:
                        response = Response.objects.get(pk=pk)
                        response.delete()
                        return JsonResponse({'status':'ok'})
                    except Response.DoesNotExist:
                         return JsonResponse({"error":"Response not found"})



            

