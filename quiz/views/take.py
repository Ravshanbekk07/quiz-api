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