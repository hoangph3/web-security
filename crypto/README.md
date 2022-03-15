### ECB

1. Thuật toán mã hóa ECB là một thuật toán mã hóa cơ bản (yếu). Đầu vào là chuỗi plain text được chia thành các block đều nhau, mỗi block có độ dài là `N` bytes (tương đương với `N` ký tự theo chuẩn ASCII do 1 byte = 1 character). Ví dụ:

```
weareneverevergettingbacktogether -> wearenevereverge||ttingbacktogethe||r
```

- Giả sử mỗi block có độ dài bằng 16 bytes, như vậy chuỗi plain text có thể được chia thành 2 block và còn dư 1 ký tự `r`. Tuy nhiên để có thể mã hóa được thì ta phải padding vào sao cho đủ 3 block. Giả sử ở đây ta padding ký tự `X` vào chuỗi -> `wearenevereverge||ttingbacktogethe||rXXXXXXXXXXXXXXX`

- Nếu như chuỗi plain text không được padding vào đầu, tức byte đầu tiên chính là byte `w`, chạy script mã hóa `python3 ecb_oracle.py weareneverevergettingbacktogether 0` ta được kết quả:

```
pt: wearenevereverge||ttingbacktogethe||rXXXXXXXXXXXXXXX||
ct: 4f67795ed2ec5e509393a30b1aad4d11||16dd4dd7c3dd517222311356a3f287e1||dfad1185bf0802000f9b6580f20ba274||
```

- Tuy nhiên để tăng độ khó cho game, thông thường plain text sẽ được padding vào đầu và cuối với các chuỗi random string, ví dụ ở đây chuỗi padding prefix là `foobarbaz1234567890` và chuỗi padding postfix là `Secret42`, ký tự padding vẫn là `X`, chạy script `python3 ecb_oracle.py weareneverevergettingbacktogether` ta có kết quả:

```
pt: foobarbaz1234567||890wearenevereve||rgettingbacktoge||therSecret42XXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||914d4e4928cf48180e0fc12ffa9e6455||862fa985d0c6692b71e0e5ab85b8dfa5||2d166151914dffb665b90a87e716a4c9||
```

2. Thuật toán ECB dễ bị khai thác, đầu tiên ta có thể tìm được `N` (số bytes trong 1 block) bằng cách thay đổi độ dài của chuỗi plain text đầu vào và dựa vào số lượng khối ciphertext trả về. Brute-force `N` với script sau:

```
for i in {1..40}; do echo $i; python3 ecb_oracle.py $(python3 -c "print('A' * $i)"); done
```

- Ở đây chúng ta thay đổi độ dài plain text từ 1 -> 40, phía server sẽ mã hóa và trả về response:

```
1
pt: foobarbaz1234567||890ASecret42XXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ada1ed6764f0e4292c850631aad51009||
2
pt: foobarbaz1234567||890AASecret42XXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||f0ac9083e90b8d23742ddf8b817201e4||
3
pt: foobarbaz1234567||890AAASecret42XX||
ct: 0215a52009de7a0105517b91b3c7e4e8||45c6cb17f887ba4ca1aa089b94947aa4||
4
pt: foobarbaz1234567||890AAAASecret42X||
ct: 0215a52009de7a0105517b91b3c7e4e8||da62a3b7a518c9befaa3875926feef6a||
5
pt: foobarbaz1234567||890AAAAASecret42||
ct: 0215a52009de7a0105517b91b3c7e4e8||6a53870f3b1dfb1974f034e3b6630a50||
6
pt: foobarbaz1234567||890AAAAAASecret4||2XXXXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||a142fdb3b3eeac6638bce8d6fe4ff343||7cb6c28a1d4ece02b7cd85fe4966f2c8||
7
pt: foobarbaz1234567||890AAAAAAASecret||42XXXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||6029b4f66b16100690be58fa4366e883||226a02ab35c35c92ff58c0a5a598e748||
8
pt: foobarbaz1234567||890AAAAAAAASecre||t42XXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||eeafbe8c8d0a95ad75ca3c436cde51e0||977a52910394964c3b51c57165b40e48||
9
pt: foobarbaz1234567||890AAAAAAAAASecr||et42XXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||a80fbb3160937fa66326bbf1cced03c8||47846f6237ec807fa35bf7a2f2c6e7fb||
10
pt: foobarbaz1234567||890AAAAAAAAAASec||ret42XXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||5279a3b06550630fad5af171bd76313b||1369ad58c45a101bebd5b9f352475e07||
11
pt: foobarbaz1234567||890AAAAAAAAAAASe||cret42XXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||14dfb3434fa92e51ca2883b2961618fb||20e48c85235cc96c075967e7abcda690||
12
pt: foobarbaz1234567||890AAAAAAAAAAAAS||ecret42XXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||e0ea1b4c9356a2081fd89c268f09c0a2||c998c36f356089bf76b49646fa4e8946||
13
pt: foobarbaz1234567||890AAAAAAAAAAAAA||Secret42XXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||77c1bd0bc4c6fce5d9f05dfc593ef7d1||
14
pt: foobarbaz1234567||890AAAAAAAAAAAAA||ASecret42XXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||4e6cf2282c993a2238f7352f8fed7307||
15
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AASecret42XXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||b6af646282ddbf5cda56510e2a3e9f02||
16
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAASecret42XXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||90dd516229e08b7c6c3bd17ddc41ad5d||
17
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAASecret42XXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||f30e3f8b674cc2f84f356c30c0ede3cb||
18
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAASecret42XXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||067d6f4adcf88f4142b32d4f1a81143f||
19
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAASecret42XX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||bc7b9454989f1539979ea9c20e42fc74||
20
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAASecret42X||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||50907298aff59ada2168354a63b2f9be||
21
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAASecret42||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||eb77f8e9016ed673dbf43160f6f1dccf||
22
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAASecret4||2XXXXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||2e125f01887000dc649263c09070af17||7cb6c28a1d4ece02b7cd85fe4966f2c8||
23
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAASecret||42XXXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||9f97cf4d21502344e7782012d2c81de5||226a02ab35c35c92ff58c0a5a598e748||
24
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAASecre||t42XXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||1f2062cce231f61e2e02b06a5faaec86||977a52910394964c3b51c57165b40e48||
25
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAASecr||et42XXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||f6bcef14352c67fd61bc9e2e607f92ba||47846f6237ec807fa35bf7a2f2c6e7fb||
26
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAASec||ret42XXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||0c2949743d515c2661b54baca0dc3e45||1369ad58c45a101bebd5b9f352475e07||
27
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAASe||cret42XXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||17879752d4238d38c4a711596884cd75||20e48c85235cc96c075967e7abcda690||
28
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAS||ecret42XXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||0fe034bf3bfb094ec51deee8384e8243||c998c36f356089bf76b49646fa4e8946||
29
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||Secret42XXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||77c1bd0bc4c6fce5d9f05dfc593ef7d1||
30
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||ASecret42XXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||4e6cf2282c993a2238f7352f8fed7307||
31
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AASecret42XXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||b6af646282ddbf5cda56510e2a3e9f02||
32
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAASecret42XXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||90dd516229e08b7c6c3bd17ddc41ad5d||
33
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAASecret42XXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||f30e3f8b674cc2f84f356c30c0ede3cb||
34
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAASecret42XXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||067d6f4adcf88f4142b32d4f1a81143f||
35
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAASecret42XX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||bc7b9454989f1539979ea9c20e42fc74||
36
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAASecret42X||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||50907298aff59ada2168354a63b2f9be||
37
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAAASecret42||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||eb77f8e9016ed673dbf43160f6f1dccf||
38
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAAAASecret4||2XXXXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||2e125f01887000dc649263c09070af17||7cb6c28a1d4ece02b7cd85fe4966f2c8||
39
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAAAAASecret||42XXXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||9f97cf4d21502344e7782012d2c81de5||226a02ab35c35c92ff58c0a5a598e748||
40
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAAAAAASecre||t42XXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||1f2062cce231f61e2e02b06a5faaec86||977a52910394964c3b51c57165b40e48||
```

Nhận xét:

- Với len(plain_text) = 6 -> số block bắt đầu tăng lên 3.
- Với len(plain_text) = 22 -> số block bắt đầu tăng lên 4.
- Với len(plain_text) = 38 -> số block bắt đầu tăng lên 5.

-> Như vậy cứ 38 - 22 = 22 - 6 = 16 ký tự thì số lượng block tăng lên 1 -> block size = N = 16.

3. Tiếp theo, ta có thể xác định được vị trí bắt đầu (còn gọi là byte offset) của chuỗi plain text, trong trường hợp plain text bị padding đầu và đuôi, ví dụ như: `prefix=foobarbaz1234567890`, `plain_text=weareneverevergettingbacktogether`, `postfix=Secret42`.

- Vị trí byte offset sẽ được tìm thấy bằng cách padding một chuỗi vào trước plain text với chiều dài plain text cố định là `2N`, cho đến khi chúng ta nhận được response là 2 block liền kề có cùng kết quả mã hóa (ciphertext). Vị trí byte offset chính là chiều dài của chuỗi mà chúng ta padding vào. Brute-force byte offset với script sau:

```
for i in {1..20}; do echo $i; python3 ecb_oracle.py $(python3 -c "print('B' * $i + 'A' * 32)"); done
```

Ở đây chúng ta cố định payload plain text = 'A' * 2 * N = 'A' * 2 * 16 = 'A' * 32. Sau đó tiến hành padding lần lượt 'B', 'BB', 'BBB', ... vào plain text và xem response:

```
0
pt: foobarbaz1234567||890AAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAASecret42XXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||ebde81de5ef1d96ef9add35ff8cadfae||a8ab74fc58026896c6b988b0fa534291||90dd516229e08b7c6c3bd17ddc41ad5d||
1
pt: foobarbaz1234567||890BAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAASecret42XXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||bcabfbc439aa11bf90089ba00ec44753||a8ab74fc58026896c6b988b0fa534291||f30e3f8b674cc2f84f356c30c0ede3cb||
2
pt: foobarbaz1234567||890BBAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAASecret42XXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||f23a92890c4378a91638a00ca792f83d||a8ab74fc58026896c6b988b0fa534291||067d6f4adcf88f4142b32d4f1a81143f||
3
pt: foobarbaz1234567||890BBBAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAASecret42XX||
ct: 0215a52009de7a0105517b91b3c7e4e8||2def5ea721747119e71039fad837977a||a8ab74fc58026896c6b988b0fa534291||bc7b9454989f1539979ea9c20e42fc74||
4
pt: foobarbaz1234567||890BBBBAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAASecret42X||
ct: 0215a52009de7a0105517b91b3c7e4e8||5fc627f3853df5bb657a7752d37b0011||a8ab74fc58026896c6b988b0fa534291||50907298aff59ada2168354a63b2f9be||
5
pt: foobarbaz1234567||890BBBBBAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAAASecret42||
ct: 0215a52009de7a0105517b91b3c7e4e8||123dbac0025144d39138c76bcac18e63||a8ab74fc58026896c6b988b0fa534291||eb77f8e9016ed673dbf43160f6f1dccf||
6
pt: foobarbaz1234567||890BBBBBBAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAAAASecret4||2XXXXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||d4db39f840de95249bb14eb3644e2c5a||a8ab74fc58026896c6b988b0fa534291||2e125f01887000dc649263c09070af17||7cb6c28a1d4ece02b7cd85fe4966f2c8||
7
pt: foobarbaz1234567||890BBBBBBBAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAAAAASecret||42XXXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||972b1dab1e5ad438f81fbf6cfbac31c6||a8ab74fc58026896c6b988b0fa534291||9f97cf4d21502344e7782012d2c81de5||226a02ab35c35c92ff58c0a5a598e748||
8
pt: foobarbaz1234567||890BBBBBBBBAAAAA||AAAAAAAAAAAAAAAA||AAAAAAAAAAASecre||t42XXXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||9832a13069ba6c13cd97a7bd6f478b86||a8ab74fc58026896c6b988b0fa534291||1f2062cce231f61e2e02b06a5faaec86||977a52910394964c3b51c57165b40e48||
9
pt: foobarbaz1234567||890BBBBBBBBBAAAA||AAAAAAAAAAAAAAAA||AAAAAAAAAAAASecr||et42XXXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||b9c4f47759f784b46174933735d3b19b||a8ab74fc58026896c6b988b0fa534291||f6bcef14352c67fd61bc9e2e607f92ba||47846f6237ec807fa35bf7a2f2c6e7fb||
10
pt: foobarbaz1234567||890BBBBBBBBBBAAA||AAAAAAAAAAAAAAAA||AAAAAAAAAAAAASec||ret42XXXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||38370aefabb12a0ba713dad6a12c0ac9||a8ab74fc58026896c6b988b0fa534291||0c2949743d515c2661b54baca0dc3e45||1369ad58c45a101bebd5b9f352475e07||
11
pt: foobarbaz1234567||890BBBBBBBBBBBAA||AAAAAAAAAAAAAAAA||AAAAAAAAAAAAAASe||cret42XXXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||c4d15af626126ab2b7fd71ce7c547754||a8ab74fc58026896c6b988b0fa534291||17879752d4238d38c4a711596884cd75||20e48c85235cc96c075967e7abcda690||
12
pt: foobarbaz1234567||890BBBBBBBBBBBBA||AAAAAAAAAAAAAAAA||AAAAAAAAAAAAAAAS||ecret42XXXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||048d532ac232a2565a1513a8894c1d52||a8ab74fc58026896c6b988b0fa534291||0fe034bf3bfb094ec51deee8384e8243||c998c36f356089bf76b49646fa4e8946||
13
pt: foobarbaz1234567||890BBBBBBBBBBBBB||AAAAAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||Secret42XXXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||8931ed3815d4a0e7974c9437309be9ab||a8ab74fc58026896c6b988b0fa534291||a8ab74fc58026896c6b988b0fa534291||77c1bd0bc4c6fce5d9f05dfc593ef7d1||
14
pt: foobarbaz1234567||890BBBBBBBBBBBBB||BAAAAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||ASecret42XXXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||8931ed3815d4a0e7974c9437309be9ab||8d5dec5568bdfe9edbba7c2b0e5b7012||a8ab74fc58026896c6b988b0fa534291||4e6cf2282c993a2238f7352f8fed7307||
15
pt: foobarbaz1234567||890BBBBBBBBBBBBB||BBAAAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AASecret42XXXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||8931ed3815d4a0e7974c9437309be9ab||ce81093a566280bf349810eb749c7023||a8ab74fc58026896c6b988b0fa534291||b6af646282ddbf5cda56510e2a3e9f02||
16
pt: foobarbaz1234567||890BBBBBBBBBBBBB||BBBAAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAASecret42XXXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||8931ed3815d4a0e7974c9437309be9ab||aaf713d1ed28cb093e765dfef5108fa2||a8ab74fc58026896c6b988b0fa534291||90dd516229e08b7c6c3bd17ddc41ad5d||
17
pt: foobarbaz1234567||890BBBBBBBBBBBBB||BBBBAAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAASecret42XXXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||8931ed3815d4a0e7974c9437309be9ab||56dd0d78592e75dc4b6b4fc0f8c2484c||a8ab74fc58026896c6b988b0fa534291||f30e3f8b674cc2f84f356c30c0ede3cb||
18
pt: foobarbaz1234567||890BBBBBBBBBBBBB||BBBBBAAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAASecret42XXX||
ct: 0215a52009de7a0105517b91b3c7e4e8||8931ed3815d4a0e7974c9437309be9ab||c0849457ae5e39860db3b0d72d891673||a8ab74fc58026896c6b988b0fa534291||067d6f4adcf88f4142b32d4f1a81143f||
19
pt: foobarbaz1234567||890BBBBBBBBBBBBB||BBBBBBAAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAASecret42XX||
ct: 0215a52009de7a0105517b91b3c7e4e8||8931ed3815d4a0e7974c9437309be9ab||6c20eb6479ca68fd94765ad4d2cf6a1f||a8ab74fc58026896c6b988b0fa534291||bc7b9454989f1539979ea9c20e42fc74||
20
pt: foobarbaz1234567||890BBBBBBBBBBBBB||BBBBBBBAAAAAAAAA||AAAAAAAAAAAAAAAA||AAAAAAASecret42X||
ct: 0215a52009de7a0105517b91b3c7e4e8||8931ed3815d4a0e7974c9437309be9ab||b9e952bc661fddcfda47d8162806506e||a8ab74fc58026896c6b988b0fa534291||50907298aff59ada2168354a63b2f9be||
```

- Nhận xét thấy với len(padding) = 13 thì ta có 2 ciphertext giống nhau liên tiếp `a8ab74fc58026896c6b988b0fa534291`. Như vậy plain text sẽ bắt đầu từ byte thứ `N - 13 + 1 = 16 - 13 + 1 = 4` của block, (trong đó 16 - 13 = 3 bytes chính là một phần của prefix, cần phải padding = 13 mới hoàn thành block = 16 bytes, do đó plain text được tính bắt đầu từ byte thứ 3 + 1 = 4). 