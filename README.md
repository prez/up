![](https://github.com/lucy/up/workflows/tests/badge.svg)

# Features

* URLs based on a seeded hash
* URL file extension determines content type
* key based authorization
* serves original file name in Content-Disposition header
* uploader IP logging
* X-Accel-Redirect support

# Example

```console
$ cat config.json
{ "external_url": "http://127.0.0.1:9111",
  "max_size": 5242880,
  "seed": "xQcUu9fcZc4ZHchjiRH3",
  "keys": [ "yvDA1zAtVDMgvEwn0mpH" ] }
$ ./up -config config.json -store store &
2019/11/27 06:30:20 listening on 127.0.0.1:9111
$ echo 'woof woof' > meow
$ curl 'http://127.0.0.1:9111' -F 'k=yvDA1zAtVDMgvEwn0mpH' -F 'f=@meow'
http://127.0.0.1:9111/VPWuV8aYDlHrexCyBEWsw_24da1MUuvHFkMrIj3W1WI.txt
$ curl -i 'http://127.0.0.1:9111/VPWuV8aYDlHrexCyBEWsw_24da1MUuvHFkMrIj3W1WI.txt'
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Disposition: inline; filename="meow"
Content-Length: 10
Content-Type: text/plain; charset=utf-8
Date: Wed, 27 Nov 2019 05:31:06 GMT

woof woof
$ curl -i 'http://127.0.0.1:9111/VPWuV8aYDlHrexCyBEWsw_24da1MUuvHFkMrIj3W1WI.jpeg'
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Disposition: inline; filename="meow"
Content-Length: 10
Content-Type: image/jpeg
Date: Wed, 27 Nov 2019 05:31:09 GMT

woof woof
$ cat store/log
2019-11-27T06:30:59+01:00 "meow" (VPWuV8aYDlHrexCyBEWsw_24da1MUuvHFkMrIj3W1WI) from 127.0.0.1
```
