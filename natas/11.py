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