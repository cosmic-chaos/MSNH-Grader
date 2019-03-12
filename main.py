import os
import webapp2
import urllib2
import jinja2
from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import mail
import json
from urlparse import urlparse


import re
import random
import string
import hashlib
import logging
import time


template_dir=os.path.join(os.path.dirname(__file__),'templates')
jinja_env=jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),autoescape=True)

class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)
        
    def render_str(self,template,**params):
        t=jinja_env.get_template(template)
        return t.render(params)
        
    def render(self,template,**kw):
    	#self.response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        #self.response.headers["Pragma"] = "no-cache"
        #self.response.headers["Expires"] = "0"    
    	
        self.write(self.render_str(template,**kw))
            
class Signup(Handler):
    def get(self):
    	user_id =self.request.cookies.get('user')
    	if user_id:
    	    u = User.get(user_id)            
            self.render('signup.html',user=u.user)
        else:
            self.render('signup.html')
        
    def post(self):    	    
        user=self.request.get('username')
        password=self.request.get('password')
        verify=self.request.get('verify')
        teacher=self.request.get('teacher')
        subject=self.request.get('subject')
        email=self.request.get('email')

        if teacher == 'on':
            if not subject:
            	subject_error="Please enter a subject."
            else:
            	subject_error=""
            teacher=True
            subject_print=subject
        else:
            teacher=False
            subject=None
            subject_error=""
            subject_print=""
         
        user_error=self.verifyUser(user)
        (password_error,verify_error)=self.verifyPass(password,verify)
        email_error=self.verifyEmail(email)
        
        if email_error is "" and user_error is "" and password_error is "" and verify_error is "" and subject_error is "":
        #if there is no error, create the hash and salt, make the new User entity, and stores the cookies
            (HASH,salt)=self.make_pw_hash(user, password)
            u = User(user=user,password=HASH,salt=salt,email=email,teacher=teacher,subject=subject)
            u_key = u.put()
            if teacher:
            	for s in subject.split(','):
            	    past_method=getFromDatabase('Method','subject = :1',s).get()
            	    if not past_method:
                        m = Method(subject=s,grading_method='fixed points')
                        m_key = m.put()
            time.sleep(.5)
            self.response.headers.add_header('Set-Cookie','user=%s; Path=/' %u_key)
            self.response.headers.add_header('Set-Cookie','pw=%s; Path=/' %HASH)
            self.response.headers.add_header('Set-Cookie','salt=%s; Path=/' %salt)
            self.redirect('/')
        else: #if there is an error pass it to the html
            user_id =self.request.cookies.get('user')
    	    if user_id:
    	        u = User.get(user_id)
                self.render('signup.html',user=u.user,username=user,user_error=user_error,email=email,email_error=email_error,password_error=password_error,verify_error=verify_error,subject_error=subject_error,subject=subject_print)
            else:
                self.render('signup.html',username=user,user_error=user_error,email=email,email_error=email_error,password_error=password_error,verify_error=verify_error,subject_error=subject_error,subject=subject_print)
                
    def verifyUser(self,user):
        USER_RE=re.compile(r"^[a-zA-Z]{3,20}$")
        if not USER_RE.match(user):
            return "That's not a valid username."
        else:
            users=db.GqlQuery('select * from User')
            for u in users:
                if u.user == user:
                    return "That user already exists."
            return ""
    
    def verifyPass(self,password,verify):
        PASS_RE=re.compile(r"^.{3,20}$")
        if not PASS_RE.match(password):
            return ("That wasn't a valid password.","")
        elif verify != password:
            return ("","Your passwords didn't match.")
        else:
            return ("","")
        
    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5)) #creates random string of 5 letters
    
    def make_pw_hash(self,name, pw):
        salt=self.make_salt()
        h= hashlib.sha256(str(name)+str(pw)+salt).hexdigest()
        return (h,salt)
        
    def verifyEmail(self,email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        if not EMAIL_RE.match(email):
            return "That's not a valid email."
        else:
            return ""

class Login(Handler):
    def get(self):
    	user_id =self.request.cookies.get('user')
    	if user_id:
    	    u = User.get(user_id) #if there is a cookie for user it gets the username from the database, needed to show in html if someones logged in
            self.render('login.html',user=u.user)
        else:
            self.render('login.html')
        
    def post(self):    	    
        user=self.request.get('username')
        password=self.request.get('password')
        result=self.verify(user,password)

        
        if result: #if the user is verified sets cookies and redirects
            password_cookie = 'pw=%s; Path=/' %result.password
            salt_cookie = 'salt=%s; Path=/' %result.salt
            self.response.headers.add_header('Set-Cookie','user=%s; Path=/' %result.key())
            self.response.headers.add_header('Set-Cookie',password_cookie.encode('UTF-8','ignore'))
            self.response.headers.add_header('Set-Cookie',salt_cookie.encode('UTF-8','ignore'))
            self.redirect('/')
        else:
            user_id =self.request.cookies.get('user')
    	    if user_id:
    	        u = User.get(user_id)
                self.render('login.html',user=u.user,Error='Invalid Login')
            else:
                self.render('login.html',Error='Invalid Login')
            
    def verify(self,u,p): #checks that there is a username like that in database, then calls verifyP
        users=db.GqlQuery('select * from User')
        for user in users:
            if user.user == u:
            	if self.verifyP(p,user.password,user.user,user.salt):
                    return user
        return False
        
    def verifyP(self,pw,HASH,name,salt): #verifies that the password hash matches the hash inputed in the function
        h= hashlib.sha256(str(name)+str(pw)+salt).hexdigest()
        if h==HASH:
            return True
        else:
            return False
        
class Logout(Handler):
    def get(self):
        self.response.delete_cookie('user')
        self.response.delete_cookie('pw')
        self.response.delete_cookie('salt')
        self.redirect('/')

    	    
class User(db.Model):
    user=db.StringProperty(required=True)
    password=db.StringProperty(required=True)
    salt=db.StringProperty(required=True)
    email=db.StringProperty(required=True)
    teacher=db.BooleanProperty(required=True)
    subject=db.StringProperty()

class Grade(db.Model):
    student=db.StringProperty(required=True)
    name=db.StringProperty(required=True)
    subject=db.StringProperty(required=True)
    variety=db.StringProperty(required=True)
    total_points=db.FloatProperty(required=True)
    points_obtained=db.FloatProperty(required=True)
    percentage=db.FloatProperty(required=True)
    date=db.DateTimeProperty(auto_now_add=True)

class Method(db.Model):
    grading_method=db.StringProperty(required=True)
    subject=db.StringProperty(required=True)

class Home(Handler):
    def get(self):
    	user_id=self.request.cookies.get('user') #checks if a user is logged in
    	title='Welcome!'
        text='Welcome to your personal grader!<br><br>'
        if user_id:
            u = User.get(user_id)

            if u.teacher is True:
            	subject=urlparse(self.request.url).query
            	if subject:
            	    text=''
            	    g=getFromDatabase('Method','subject=:1',subject).get()
            	    (table,link)=self.makeTable(u.teacher,subject,u.user,g.grading_method)
            	    title=subject
                elif len(u.subject.split(",")) > 1:
            	    link=''
            	    table=''
            	    for subject in u.subject.split(","):
            	    	link+='<a href="/?'+subject+'">'+subject+'</a><br><br>'
                else:
                    g=getFromDatabase('Method','subject=:1',u.subject).get()
            	    (table,link)=self.makeTable(u.teacher,u.subject,u.user,g.grading_method)
            else:
            	(table,link)=self.makeTable(False,None,u.user,None)
            self.render('home.html',user=u.user,table=table,title=title,link=link,text=text,teacher=u.teacher)
        else:
             link='<i><b>Please <a href="/signup">signup</a> for an account, or <a href="/login">login</a> if you already have one.</b></i>'
             self.render('home.html',link=link,title=title,text=text)
            
    def makeTable(self,teacher,subject,user,grading):
        table="""<table>
	    <tr id='header'>
	    <td>Last Updated</td>"""
		
        if teacher is True:
            people=getFromDatabase('User','teacher = :1 order by user asc',False)
            link="<a href='/grading_method?"+subject+"'>Your Grading Method</a> | <a href='/add_all_grade?"+subject+"'>Add a Grade</a>"
            table+="<td>Student</td>"
        else:
            people=db.GqlQuery('select * from Method')
            link='<a href="http://rogerhub.com/final-grade-calculator/">Calculate Percentage Needed on Item to Get Certain Grade</a>'
            table+="<td>Subject</td>"
		
	table+="""<td>Overall Grade</td>
	    <td>Overall Letter Grade</td>
	    </tr>"""
	subjects=list()
        for p in people:
            if teacher is True:
            	overall=get_overall(p.user,subject,grading)
                last_updated=self.last_updated(p.user,subject)
                table+="<tr>"
                table+="<td>"+str(last_updated)+"</td>"
                table+="<td><a href='/"+p.user+"?"+subject+"'>"+p.user+"</a></td>"
                if overall == 'No Grade':
                    table+="<td>"+overall+"</td>"
                    table+="<td>No Grade</td>"
                else:
                    table+="<td>"+overall+"%</td>"
                    table+="<td>"+getLetterGrade(overall)+"</td>"
                table+="</tr>"
            else:
	        overall=get_overall(user,p.subject,p.grading_method)
		last_updated=self.last_updated(user,p.subject)
		table+="<tr>"
		table+="<td>"+str(last_updated)+"</td>"
		subjects.append(p.subject)
		table+="<td><a href='/"+p.subject+"'>"+p.subject+"</a></td>"
		if overall == 'No Grade':
		    table+="<td>"+overall+"</td>"
		    table+="<td>No Grade</td>"
		else:
		    table+="<td>"+overall+"%</td>"
		    table+="<td>"+getLetterGrade(overall)+"</td>"
		table+="</tr>"
                    	
        table+="</table>" 
            
        return (table,link) #if the user is logged in it sends the username to the html
        
    def last_updated(self,student,subject):
    	grades=getFromDatabase('Grade','student = :1 order by date desc',student)
    	
    	grades_list=list()
        for g in grades:
	    if g.subject == subject:
	        grades_list.append(g)
	try:
	    last_updated=grades_list[0].date.strftime("%x")
	except:
	    last_updated="---"
	return last_updated

class indGrades(Handler):
    def get(self):
    	user_id=self.request.cookies.get('user')
	if user_id:
            u = User.get(user_id)
	    url = urlparse(self.request.url).path[1:]
	    if u.teacher is True:
		subject=urlparse(self.request.url).query
	    	link="<a href='/add_grade?"+url+"+"+subject+"'>Add a Grade</a><br><br>"
	    	grades=getFromDatabase('Grade','student = :1 order by date desc',url)
		url = str(url)+"'s Grades"
	    else:
	    	grades=getFromDatabase('Grade','student = :1 order by date desc',u.user)
		link=''
		subject=url
		
            table=''
	    for g in grades:
	        if g.subject == subject:
	            table+="<tr>"
       		    table+="<td>"+str(g.date.strftime("%x"))+"</td>"
		    table+="<td>"+g.name+"</td>"
		    table+="<td>"+g.variety+"</td>"
		    table+="<td>"+str(('%f' % g.points_obtained).rstrip('0').rstrip('.'))+"</td>"
		    table+="<td>"+str(('%f' % g.total_points).rstrip('0').rstrip('.'))+"</td>"
		    table+="<td>"+str(('%f' % g.percentage).rstrip('0').rstrip('.'))+"%</td>"
		    table+="<td>"+str(getLetterGrade(g.percentage))+"</td>"
		    if u.teacher is True:
		    	table+="<td><a href='/edit_grade?"+str(g.key().id())+"'>Edit</a></td>"
		    	table+="<td><a href='/delete_grade?"+str(g.key().id())+"'>Delete</a></td>"
		    table+="</tr>"

	    self.render('page.html',user=u.user,url=url,table=table,link=link,teacher=u.teacher)
	else:
	    self.redirect('/login')
	    
class addAllGrade(Handler):
    def get(self):
    	user_id =self.request.cookies.get('user')
    	if user_id:
    	    u = User.get(user_id)
            students=getFromDatabase('User','teacher=:1',False)
            self.render('addGrade.html',user=u.user,students=enumerate(students))
        else:
            self.redirect('/login')
    def post(self):
    	user_id =self.request.cookies.get('user')
	u = User.get(user_id)
    	 
    	subject=urlparse(self.request.url).query
        gradename=self.request.get('gradename')
        variety=self.request.get('variety')
        possible=self.request.get('points_possible')
        possible_error=verifyPoints(possible)
        students=getFromDatabase('User','teacher=:1',False)
        obtained_list=list()
        obtained_error_list=list()
        
        for s in students:
            obtained_list.append(self.request.get(s.user))
            obtained_error_list.append(verifyPoints(self.request.get(s.user)))
        
        for element in obtained_error_list:
            if element != "":
                obtained_error=True
                break
            else:
            	obtained_error=""
        
        if obtained_error is "" and possible_error is "":
            for i,s in enumerate(students):
                percentage=float(obtained_list[i])/float(possible)*100
                g = Grade(student=str(s.user),name=gradename,variety=variety,total_points=float(possible),points_obtained=float(obtained_list[i]),percentage=percentage,subject=subject)
                g_key = g.put()
                time.sleep(.5)
                
                method=getFromDatabase('Method','subject=:1',subject).get()
                letter_grade=getLetterGrade(get_overall(str(s.user),subject,str(method.grading_method)))
                message=sendMail(str(s.email),str(s.user),subject,letter_grade,"Your Grade Has Been Updated",None)
            
            if len(u.subject.split(','))==1:
            	self.redirect('/')
            else:
                self.redirect('/?'+subject)
        else: #if there is an error pass it to the html
            user_id =self.request.cookies.get('user')
    	    if user_id:
    	        u = User.get(user_id)
                self.render('addGrade.html',user=u.user,students=enumerate(students),possible_error=possible_error,obtained_error=obtained_error_list,points_obtained=obtained_list,points_possible=possible,gradename=gradename,variety=variety)
            else:
                self.redirect('/login')
	
class addGrade(Handler):
    def get(self):
    	user_id =self.request.cookies.get('user')
    	if user_id:
    	    u = User.get(user_id)    	    
            self.render('addGrade.html',user=u.user)
        else:
            self.redirect('/login')
        
    def post(self):  	
    	user_id =self.request.cookies.get('user')
	u = User.get(user_id)
    	 
    	student=urlparse(self.request.url).query.split('+')[0]
    	subject=urlparse(self.request.url).query.split('+')[1]
    	
        gradename=self.request.get('gradename')
        variety=self.request.get('variety')
        possible=self.request.get('points_possible')
        obtained=self.request.get('points_obtained')
        
        obtained_error=verifyPoints(obtained)
        possible_error=verifyPoints(possible)
        
        
        if obtained_error is "" and possible_error is "":
            percentage=float(obtained)/float(possible)*100
            g = Grade(student=str(student),name=gradename,variety=variety,total_points=float(possible),points_obtained=float(obtained),percentage=percentage,subject=subject)
            g_key = g.put()
            time.sleep(.5)
            g=getFromDatabase('Method','subject=:1',subject).get()
            letter_grade=getLetterGrade(get_overall(str(student),subject,str(g.grading_method)))
            s=getFromDatabase('User','user=:1',student).get()
            message=sendMail(str(s.email),str(student),subject,letter_grade,"Your Grade Has Been Updated",None)
            self.redirect('/'+student+'?'+subject)
        else: #if there is an error pass it to the html
            user_id =self.request.cookies.get('user')
    	    if user_id:
    	        u = User.get(user_id)
                self.render('addGrade.html',user=u.user,possible_error=possible_error,obtained_error=obtained_error,points_obtained=obtained,points_possible=possible,gradename=gradename,variety=variety)
            else:
                self.redirect('/login')

class gradingMethod(Handler):
    def get(self):
    	user_id =self.request.cookies.get('user')
    	if user_id:
    	    u = User.get(user_id)    
	    subject=urlparse(self.request.url).query
	    g=getFromDatabase('Method','subject=:1',subject).get()
	    
	    current="Currently, your grading method "
            if g.grading_method == 'fixed points':
            	current+='is the fixed point system.'
            else:
            	method=g.grading_method.split(',')
            	current+='uses '+str(method[0])+'% of homework, '+str(method[1])+'% of tests, '+str(method[2])+'% of presentations, and '+str(method[3])+'% of projects.'
            	
            self.render('gradingMethod.html',user=u.user,current=current)
        else:
            self.redirect('/login')
    def post(self):
  	user_id =self.request.cookies.get('user')
    	if user_id:
    	    u = User.get(user_id)
            grading_method=self.request.get('radio')
            subject=urlparse(self.request.url).query
            g=getFromDatabase('Method','subject=:1',subject).get()
            
            current="Currently, your grading method"
            if g.grading_method == 'fixed points':
            	current+='is the fixed point system.'
            else:
            	method=g.grading_method.split(',')
            	current+='uses '+str(method[0])+'% homework, '+str(method[1])+'% tests, '+str(method[2])+'% presentations, and '+str(method[3])+'% projects.'
            
            if grading_method == 'fixed':
                g.grading_method = 'fixed points'
                g.put()
                self.redirect('/')
            elif grading_method == 'percent':
                hmwk=self.request.get('hmwk')
                test=self.request.get('test')
                pres=self.request.get('pres')
                proj=self.request.get('proj')
                
                error=self.verify(hmwk,test,pres,proj)
                
                if error is "":
                    g.grading_method = str(hmwk+','+test+','+pres+','+proj)
                    g.put()
                    self.redirect('/')
                else:
                    self.render('gradingMethod.html',user=u.user,error=error,hmwk=hmwk,test=test,pres=pres,proj=proj,current=current)
            else:
            	self.render('gradingMethod.html',user=u.user,error=grading_method,current=current)#"Please choose an option.")

        else:
            self.redirect('/login')
                
    def verify(self,hmwk,test,pres,proj):
        try:
            hmwk=float(hmwk)
            test=float(test)
            pres=float(pres)
            proj=float(proj)
        except:
            return 'Make sure you enter a number.'
            
        if hmwk+test+pres+proj == 100:
            return ""
        else:
            return "Make sure the numbers entered equal to 100."

class editGrade(Handler):
    def get(self):
    	user_id =self.request.cookies.get('user')
	if user_id:
    	    u = User.get(user_id)    	    
            grade_id=urlparse(self.request.url).query
    	    grade=Grade.get_by_id(int(grade_id))
    	    self.render('addGrade.html',user=u.user,points_obtained=grade.points_obtained,points_possible=grade.total_points,gradename=grade.name,variety=grade.variety)
        else:
            self.redirect('/login')
        
    def post(self):
    	user_id =self.request.cookies.get('user')
	u = User.get(user_id)
    	 
    	grade_id=urlparse(self.request.url).query
    	grade=Grade.get_by_id(int(grade_id))
    	student=grade.student
    	subject=grade.subject
    	
        gradename=self.request.get('gradename')
        variety=self.request.get('variety')
        possible=self.request.get('points_possible')
        obtained=self.request.get('points_obtained')
        
        obtained_error=verifyPoints(obtained)
        possible_error=verifyPoints(possible)
        
        
        if obtained_error is "" and possible_error is "":
            percentage=float(obtained)/float(possible)*100
            g = Grade(student=str(student),name=gradename,variety=variety,total_points=float(possible),points_obtained=float(obtained),percentage=percentage,subject=subject)
            g_key = g.put()
            Grade.delete(grade)
            time.sleep(.5)
            self.redirect('/'+student+'?'+subject)
        else: #if there is an error pass it to the html
            user_id =self.request.cookies.get('user')
    	    if user_id:
    	        u = User.get(user_id)
                self.render('addGrade.html',user=u.user,possible_error=possible_error,obtained_error=obtained_error,points_obtained=obtained,points_possible=possible,gradename=gradename,variety=variety)
            else:
                self.redirect('/login')
    	    
class deleteGrade(Handler):
    def get(self):
    	grade_id=urlparse(self.request.url).query
    	grade=Grade.get_by_id(int(grade_id))
    	student=grade.student
    	subject=grade.subject
        Grade.delete(grade)
        time.sleep(.1)
    	self.redirect('/'+student+'?'+subject)

#class forgot_password(Handler):
#    def get(self):
#    	grade_id=urlparse(self.request.url).query
#    	sendMail(email,name,subject,grade,'Forgot Email','Your password is')
    	
    	
def verifyPoints(points):
    try:
        points=float(points)
        return ''
    except:
        return "That's not a valid grade."

def get_overall(student,subject,grading_method):
    grades=getFromDatabase('Grade','student = :1',student)
    total_points=0
    points_obtained=0
    
    grades_array=list()
    for g in grades:
        if g.subject == subject:
	    grades_array.append(g)
    
    if grading_method == 'fixed points':
        for g in grades_array:
    	    if g.variety != "Extra Credit":
                total_points+=float(g.total_points)
            points_obtained+=float(g.points_obtained)
    else:
    	grading_method=grading_method.split(',')
    	total_hmwk=0
    	total_test=0
    	total_pres=0
    	total_proj=0
    	extra=0
    	
    	obt_hmwk=0
    	obt_test=0
    	obt_pres=0
    	obt_proj=0
    	for g in grades_array:
    	    if g.variety == "Homework":
    	        total_hmwk+=float(g.total_points)
    	        obt_hmwk+=float(g.points_obtained)
    	    elif g.variety == "Test":
    	        total_test+=float(g.total_points)
    	        obt_test+=float(g.points_obtained)
    	    elif g.variety == "Presentation":
    	        total_pres+=float(g.total_points)
    	        obt_pres+=float(g.points_obtained)   
    	    elif g.variety == "Project":
    	    	total_proj+=float(g.total_points)
    	        obt_proj+=float(g.points_obtained)
    	    elif g.variety == "Extra Credit":
    	    	extra+=float(g.points_obtained)
    	    	
        total_points=total_hmwk*float(grading_method[0])+total_test*float(grading_method[1])+total_pres*float(grading_method[2])+total_proj*float(grading_method[3])
        points_obtained=extra+obt_hmwk*float(grading_method[0])+obt_test*float(grading_method[1])+obt_pres*float(grading_method[2])+obt_proj*float(grading_method[3])
        
    try:
        percentage=float(points_obtained)/float(total_points) * 100
        strip=('%f' % percentage).rstrip('0').rstrip('.')
        overall=str(strip)
    except:
        overall='No Grade'
        
    return overall
        
def getLetterGrade(points):
    points=float(points)
    if points >= 90:
        if points<95:
    	    grade='A-'
    	elif points<=100:
    	    grade='A'
    	elif points>100:
    	    grade='A+'
    elif points >= 80:
        if points<84:
            grade='B-'
        elif points<87:
            grade='B'
        else:
            grade='B+'
    elif points >= 70:
        if points<74:
            grade='C-'
        elif points<77:
            grade='C'
        else:
            grade='C+'
    elif points >= 60:
        if points<64:
            grade='F-'
        elif points<67:
            grade='F'
        else:
            grade='F+'
    else:
        grade='F- (Good Luck!)'
    return grade

def sendMail(email,name,subject,grade,mail_subject,body):
    message = mail.EmailMessage(sender="MSNH Grader <grader@msnh.org>",
                            subject=mail_subject)    

    message.to = email
    
    if body:
    	message.body=body
    else:
        message.body = """Dear """+name+""",

Your """+subject+""" grade has been updated.
Your overall letter grade is now """+grade+""".
View your grade at msnh-grader.appspot.com.

The MSNH Grader
"""

    message.send()
    
def getFromDatabase(database,where,value):
    command='select * from '+database+' where '+where
    elements=db.GqlQuery(command,value)
    return elements
        
PAGE_RE = '(?:[ a-zA-Z])*'
app = webapp2.WSGIApplication([
    ('/', Home),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/add_grade', addGrade),
    ('/add_all_grade', addAllGrade),
    ('/edit_grade', editGrade),
    ('/delete_grade', deleteGrade),
    #('/forgot_password', forgotPassword),
    ('/grading_method', gradingMethod),
    ('/'+PAGE_RE, indGrades),
], debug=True)
