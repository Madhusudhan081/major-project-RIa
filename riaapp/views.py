from django.shortcuts import render,redirect
from django.contrib import messages
import re
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from .utils import TokenGenerator,generate_token
from django.utils.encoding import force_bytes,force_text,DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
from django.views.generic import View
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from riaapp.models import Register,Contact,Payments,Courses,Documents,Certificate,Attendace
# Create your views here.
def index(request):
    return render(request, "home.html")
    
def about(request):
    return render(request, "about.html")


def handleSignin(request):
    if request.method=="POST":
        flag = 0
        name=request.POST['name']
        email=request.POST['email']
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        if password!=confirm_password:
            messages.warning(request,"Password is Not Matching")
            return redirect('/signin') 
        if len(password)<=8:
            messages.warning(request,"Password must be atleast 8 character")
            return redirect('/signin') 
        elif not re.search("[a-z]", password):
            flag = -1
            
        elif not re.search("[A-Z]", password):
            flag = -1
            
        elif not re.search("[0-9]", password):
            flag = -1
            
        elif not re.search("[_@$]" , password):
            flag = -1  
        else:
            pass


       
        if(flag==0):           
            #logic for backend signup starts from here
            try:
                if User.objects.get(username=email):
                # return HttpResponse("email already exist")
                    messages.info(request,"Email is Taken")
                    return redirect('/signin')


            except Exception as identifier:
                pass


            user = User.objects.create_user(email,email,password)
            user.first_name=name
            user.is_active=False
            user.save()
            email_subject="Activate Your Account"
            message=render_to_string('activate.html',{
                'user':user,
                'domain':'127.0.0.1:8000',
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':generate_token.make_token(user)

            })

            #email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
            #email_message.send()
            # messages.success(request,f"Activate Your Account by clicking the link in your gmail {message}")
            messages.success(request,f"{message}")
           
            return redirect('/login')

        else:
            messages.error(request, "password not valid")
            return redirect('/signin')


        
        
    return render(request, "signin.html")




class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_text(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('/login')
        return render(request,'activatefail.html')


def handleLogin(request):
    if request.method=="POST":
        username=request.POST['email']
        userpassword=request.POST['pass1']
        myuser=authenticate(username=username,password=userpassword)

        if myuser is not None:
            login(request,myuser)
            messages.success(request,"Login Success")
            return redirect('/enroll')

        else:
            messages.error(request,"Invalid Credentials")
            return redirect('/login')

    return render(request, "login.html")

def handleLogout(request):
    logout(request)
    messages.success(request,"Logout Success")
    return render(request,"login.html")


class RequestResetEmailView(View):
    def get(self,request):
        return render(request,'request-reset-email.html')

    def post(self,request):

        email=request.POST['email']
        user=User.objects.filter(email=email)

        if user.exists():
            # current_site=get_current_site(request)
            email_subject='[Reset Your Password]'
            message=render_to_string('reset-user-password.html',{
                'domain':'127.0.0.1:8000',
                'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token':PasswordResetTokenGenerator().make_token(user[0])
            })

            # email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
            # email_message.send()

            messages.info(request,f"{message} " )
            return render(request,'request-reset-email.html')
        else:
            messages.error(request,'No Account Exists with this email' )
            return render(request,'request-reset-email.html')

class SetNewPasswordView(View):
    def get(self,request,uidb64,token):
        context = {
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id=force_text(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)

            if  not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,"Password Reset Link is Invalid")
                return render(request,'request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            pass

        return render(request,'set-new-password.html',context)

    def post(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        flag = 0
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        if password!=confirm_password:
            messages.warning(request,"Password is Not Matching")
            return render(request,'set-new-password.html',context)
        
        if len(password)<=8:
            messages.warning(request,"Password must be atleast 8 character")
            return render(request,'set-new-password.html',context)
        elif not re.search("[a-z]", password):
            flag = -1
            
        elif not re.search("[A-Z]", password):
            flag = -1
            
        elif not re.search("[0-9]", password):
            flag = -1
            
        elif not re.search("[_@$]" , password):
            flag = -1  
        else:
            pass


       
        if(flag==0):  
            try:
                user_id=force_text(urlsafe_base64_decode(uidb64))
                user=User.objects.get(pk=user_id)
                user.set_password(password)
                user.save()
                messages.success(request,"Password Reset Success Please Login with NewPassword")
                return redirect('/login')

            except DjangoUnicodeDecodeError as identifier:
                messages.error(request,"Something Went Wrong")
                return render(request,'set-new-password.html',context)

        
def enroll(request):
    if not request.user.is_authenticated:
        messages.warning(request,"Please Login & Register with us")
        return redirect("/login")
    courses=Courses.objects.all()
    context={"courses":courses}
    if request.method=="POST":
        fname=request.POST.get('fname')
        lname=request.POST.get('lname')
        fatherName=request.POST.get('fatherName')
        phone=request.POST.get('phone')
        alternateNumber=request.POST.get('alternateNumber')
        email=request.POST.get('email')
        college=request.POST.get('college')
        addr=request.POST.get('addr')
        landmark=request.POST.get('landmark')
        street=request.POST.get('street')
        pcode=request.POST.get('pcode')
        city=request.POST.get('city')
        companyname=request.POST.get('companyname')
        Designation=request.POST.get('Designation')
        Qualification=request.POST.get('Qualification')
        cknowledge=request.POST.get('cknowledge')
        scourse=request.POST.get('scourse')
        ccourse=request.POST.get('ccourse')
        emailPresent=Register.objects.filter(email=email)
        if emailPresent:
            messages.error(request,"Email is already Taken")
            return redirect('/enroll')


        if scourse==ccourse:
            pass
        else:
            messages.error(request,"Please Select the Valid Course...")
            return redirect('/enroll')
        query=Register(firstName=fname,lastName=lname,fatherName=fatherName,phoneNumber=phone,alternateNumber=alternateNumber,email=email,collegeName=college,address=addr,landmark=landmark,street=street,city=city,pincode=pcode,companyName=companyname,designation=Designation,qualification=Qualification,computerKnowledge=cknowledge,Course=scourse)
        # print(query.candidateId)
        query.save()
        messages.success(request,"Enrollment Success")
        return redirect('/candidateprofile')



    return render(request,"enroll.html",context)

def courses(request):
    courses=Courses.objects.all()
    context={"courses":courses}
    return render(request,"courses.html",context)

def course(request,id):
    course=Courses.objects.filter(id=id)
    context={"course":course}
    return render(request,"course.html",context)


def attendance(request):
    if not request.user.is_authenticated:
        messages.warning(request,"Please Login & Apply Attendance")
        return redirect("/login")
    if request.method=="POST":
        name=request.POST.get('name')
        email=request.POST.get('email')
        date=request.POST.get('date')
        logintime=request.POST.get('logintime')
        logouttime=request.POST.get('logouttime')
        query=Attendace(name=name,email=email,date=date,logintime=logintime,logouttime=logouttime)
        query.save()
        messages.success(request,"Applied Successfully wait for the approval")
        return redirect("/candidateprofile")

    return render(request,"attendance.html")


def contact(request):
    if request.method=="POST":
        name=request.POST.get('name')
        email=request.POST.get('email')
        phoneNo=request.POST.get('num')
        desc=request.POST.get('desc')
        query=Contact(name=name,email=email,phoneNumber=phoneNo,description=desc)
        query.save()
        messages.success(request,"Thanks for Contacting us we will get back you soon...")
        return render(request,"contact.html")
    return render(request,"contact.html")



def profile(request):
    if not request.user.is_authenticated:
        messages.warning(request,"Please Login & View Your Profile")
        return redirect("/login")
    currentuser=request.user.username
    print(currentuser)
    details=Register.objects.filter(email=currentuser)
    payment=Payments.objects.all()
    paymentstatus=""
    amount=0
    balance=0
    for j in payment:
        if str(j.name)==currentuser :
            print(j.name,type(str(j.name)))
            print('matching')
            paymentstatus=j.status
            amount=j.amountPaid
            balance=j.balance

    # print(paymentstatus)
    # print(amount)
    # print(balance)
    # print(details)
    paymentstats={"paymentstatus":paymentstatus,"amount":amount,"balance":balance}

    attendanceStats=Attendace.objects.filter(email=currentuser)   
    context={"details":details,"status":paymentstats,"attendanceStats":attendanceStats}
    return render(request,"profile.html",context)

def candidateupdate(request,id):
    data=Register.objects.get(candidateId=id) 
    courses=Courses.objects.all()
    context={"data":data,"courses":courses}
    if request.method=="POST":
        fname=request.POST.get('fname')
        lname=request.POST.get('lname')
        fatherName=request.POST.get('fatherName')
        phone=request.POST.get('phone')
        alternateNumber=request.POST.get('alternateNumber')
        college=request.POST.get('college')
        addr=request.POST.get('addr')
        landmark=request.POST.get('landmark')
        street=request.POST.get('street')
        pcode=request.POST.get('pcode')
        city=request.POST.get('city')
        companyname=request.POST.get('companyname')
        Designation=request.POST.get('Designation')
        Qualification=request.POST.get('Qualification')
        scourse=request.POST.get('scourse')
       
        edit=Register.objects.get(candidateId=id)
        edit.firstName=fname
        edit.lastName=lname
        edit.fatherName=fatherName
        edit.phoneNumber=phone
        edit.alternateNumber=alternateNumber
        edit.collegeName=college
        edit.address=addr
        edit.landmark=landmark
        edit.street=street
        edit.city=city
        edit.pincode=pcode
        edit.companyName=companyname
        edit.designation=Designation
        edit.qualification=Qualification
        edit.Course=scourse
        edit.save()
        messages.info(request,"Data Updates Successfully...")
        return redirect("/candidateprofile")

    return render(request,"updatecandidate.html",context)