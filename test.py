from flask import Flask,render_template,flash,redirect,url_for,session,logging,request
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps
import subprocess 
import os
from werkzeug.utils import secure_filename
import re
import imghdr
import os
from flask import Flask, render_template, request, redirect, url_for, abort, send_from_directory
from werkzeug.utils import secure_filename
import threading
from queue import Queue
import time
import socket
import pyfiglet 

# Kullanıcı Giriş Decorator'ı
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu sayfayı görüntülemek için lütfen giriş yapın.","danger")
            return redirect(url_for("login"))

    return decorated_function


#kullanıcı giriş formu
class DashbordForm(Form):
    cmd = StringField("Komut Calıstırma")
    portscan = StringField("Port Scan")

#kullanıcı giriş formu
class LoginForm(Form):
    username = StringField("Kullanıcı Adı")
    password = PasswordField("Parola")


#kullanıcı kayıt form kontrollu
class RegisterForm(Form):
    name = StringField("İsim Soyisim",validators=[validators.Length(min = 4,max = 25)])
    username = StringField("Kullanıcı Adı",validators=[validators.Length(min = 5,max = 35)])
    email = StringField("Email Adresi",validators=[validators.Email(message = "Lütfen Geçerli Bir Email Adresi Girin...")])
    password = PasswordField("Parola:",validators=[
        validators.DataRequired(message = "Lütfen bir parola belirleyin"),
        validators.EqualTo(fieldname = "confirm",message="Parolanız Uyuşmuyor...")
    ])
    confirm = PasswordField("Parola Doğrula")


app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['UPLOAD_PATH'] = 'uploads'

#veritabanı key oluşturma ve bağlantı sağlanma
app.secret_key= "load_test"

app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "ybblog"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"
mysql = MySQL(app)

#index sayfasına giris
@app.route("/")
def index():
   return render_template("index.html")

@app.route('/about')
def about():
    return render_template("/about.html")

#Kayıt Olma
@app.route("/register",methods = ["GET","POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        cursor = mysql.connection.cursor()

        sorgu = "Insert into users(name,email,username,password) VALUES(%s,%s,%s,%s)"

        cursor.execute(sorgu,(name,email,username,password))
        mysql.connection.commit()

        cursor.close()
        flash("Başarıyla Kayıt Oldunuz...","success")
        return redirect(url_for("login"))
    else:
        return render_template("register.html",form = form)
#kullanıcı giris bölümü

@app.route("/login",methods =["GET","POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST":
       username = form.username.data
       password_entered = form.password.data

       cursor = mysql.connection.cursor()

       sorgu = "Select * From users where username = %s"

       result = cursor.execute(sorgu,(username,))

       if result > 0:
           data = cursor.fetchone()
           real_password = data["password"]
           if sha256_crypt.verify(password_entered,real_password):
               flash("Başarıyla Giriş Yaptınız...","success")
                #sesin olusturmaya basladık
               session["logged_in"] = True
               session["username"] = username

               return redirect(url_for("dashboard"))
           else:
               flash("Parolanızı Yanlış Girdiniz...","danger")
               return redirect(url_for("login")) 

       else:
           flash("Böyle bir kullanıcı bulunmuyor...","danger")
           return redirect(url_for("login"))

    return render_template("login.html",form = form)

#dashboard islemi

@app.route("/dashboard",methods =["GET","POST"])
@login_required
def dashboard():


    return render_template("dashboard.html")

@app.route("/result",methods =["GET","POST"])
@login_required
def result():
     
    if request.method == "POST":
                 
       sonuc = request.form['sonuc']
       islem = subprocess.Popen(sonuc, shell = True, stdout = subprocess.PIPE)
       cikti = islem.communicate()[0] 
       

       cikti=str(cikti)
      
       print(cikti)
    else:
        pass
    return render_template('result.html',sonuc=cikti)

@app.route("/tarama",methods =["GET","POST"])
@login_required
def tarama():
    
    if request.method == "POST":

        portscan = request.form['portscan']
       
         # Add Banner  
   
        try:
             for port in range(1,100):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                socket.setdefaulttimeout(1) 
          
                # returns an error indicator 
                result = s.connect_ex((portscan,port)) 
                if result ==0:
                        
                     #print("Port {} is open".format(port)) 
                     ss = "port open " + str(port)
                        
                     s.close() 
             return render_template('tarama.html',portscan=ss)
        except KeyboardInterrupt: 
            print("\n Exitting Program !!!!") 
            sys.exit() 
        except socket.gaierror: 
            print("\n Hostname Could Not Be Resolved !!!!") 
            sys.exit() 
        except socket.error: 
            print("\ Server not responding !!!!") 
            sys.exit() 
    else:
        pass
    return render_template('tarama.html')

# Logout İşlemi
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = imghdr.what(None, header)
    if not format:
        return None
    return '.' + (format if format != 'jpeg' else 'jpg')

@app.errorhandler(413)
@login_required
def too_large(e):
    return "File is too large", 413

@app.route('/fileupload')
@login_required
def fileupload():
    files = os.listdir(app.config['UPLOAD_PATH'])
    return render_template('fileupload.html', files=files)

@app.route('/', methods=['POST'])
@login_required
def upload_files():
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS'] or \
                file_ext != validate_image(uploaded_file.stream):
            return "Invalid image", 400
        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))
    return '', 204

@app.route('/uploads/<filename>')
def upload(filename):
    return send_from_directory(app.config['UPLOAD_PATH'], filename)

@app.route("/raporlama",methods =["GET","POST"])
@login_required
def raporlama():
 
    return render_template("raporlama.html")

if __name__ == "__main__":
    app.run(debug=True)
