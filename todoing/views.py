from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login,logout, authenticate
from .forms import TodoForm
from .models import Todo
from django.utils import timezone
from django.contrib.auth.decorators import login_required

def home(request):
	return render(request, 'todoing/home.html')



def signupuser(request):
	if request.method == 'GET':

		return render(request, 'todoing/signupuser.html', {'form': UserCreationForm()})

	else:
		if request.POST['password1'] == request.POST['password2']:
			try:
				user = User.objects.create_user(request.POST['username'], password = request.POST['password1'])
				user.save()
				login(request, user)
				return redirect('currenttodo')
			except IntegrityError:
				return render(request, 'todoing/signupuser.html', {'form': UserCreationForm(), 'error': 'This is username already been taken. Please choose a new username'})
		else:
			#Несоответствие пароля, сообщение
			return render(request, 'todoing/signupuser.html', {'form': UserCreationForm(), 'error': 'Password did not match'})


def loginuser(request):
	if request.method == 'GET':

		return render(request, 'todoing/loginuser.html', {'form': AuthenticationForm()})

	else:
		user = authenticate(request, username = request.POST['username'], password = request.POST['password'])
		if user is None:
			return render(request, 'todoing/loginuser.html', {'form': AuthenticationForm(), 'error': 'Username and password din not match'} , )
		else:
			login(request, user)
			return redirect('currenttodo')

@login_required
def logoutuser(request):
	if request.method=='POST':
		logout(request)
		return redirect('home')
@login_required
def createtodo(request):
	if request.method == 'GET':
		return render(request, 'todoing/createtodo.html', {'forms': TodoForm()})
	else:
		try:
			forms = TodoForm(request.POST)
			newtodo = forms.save(commit = False)
			newtodo.user = request.user
			newtodo.save()
			return redirect('currenttodo')
		except ValueError:
			return render(request, 'todoing/createtodo.html', {'forms': TodoForm(), 'error':'Bad data passed in. Try again.'})


@login_required
def currenttodo(request):
	todos = Todo.objects.filter(user = request.user, datecomplited__isnull = True)
	return render(request, 'todoing/currenttodo.html', {'todos':todos})
@login_required
def completedtodo(request):
	todos = Todo.objects.filter(user = request.user, datecomplited__isnull = False).order_by('-datecomplited')
	return render(request, 'todoing/completedtodo.html', {'todos':todos})
@login_required
def viewtodo(request, todo_pk):
	todo = get_object_or_404(Todo, pk = todo_pk, user = request.user)

	if request.method == 'GET':
		forms = TodoForm(instance = todo)
		return render(request, 'todoing/viewtodo.html', {'todo':todo, 'forms':forms})
	else:
		try:
			forms = TodoForm(request.POST, instance = todo )
			forms.save()
			return redirect('currenttodo')

		except ValueError:
			return render(request, 'todoing/viewtodo.html', {'todo':todo, 'forms':forms, 'error':'Bad Info'})
@login_required
def completetodo(request, todo_pk):
	todo = get_object_or_404(Todo, pk = todo_pk, user = request.user)
	if request.method=='POST':
		todo.datecomplited = timezone.now()
		todo.save()
		return redirect('currenttodo')

@login_required
def deletetodo(request, todo_pk):
	todo = get_object_or_404(Todo, pk = todo_pk, user = request.user)
	if request.method == 'POST':
		
		todo.delete()
		return redirect('currenttodo')

