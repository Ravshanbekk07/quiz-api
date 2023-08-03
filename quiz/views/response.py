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


class ResponseView(View):
    def get(self,request,take_id):
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

            answers = Response.objects.filter(take=take_id)
            results =[]
            for answer in answers:
                results.append({
                    'question':answer.question.content,
                    
                    'is_correct':answer.option.is_correct
                })
            return  JsonResponse( results,safe=False)
      

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



            

