:: ---------------------------------------------------------
:: FPLive_win - Forensic-Proof Live ToolKit v1.1
:: ---------------------------------------------------------
::
:: Collection Order of Digital Evidence
:: ---------------------------------------------------------
1. (non-volatile) Prefetch, Superfetch, RecentFileCache.bcf
2. (volatile) Network Information
3. (volatile) Physical Memory
4. (volatile) Process Information
5. (volatile) Logon User Information
6. (volatile) System Information
7. (volatile) Network Interface Information
8. (volatile) Password Information
9. (volatile) MISCs Information
10. (non-volatile) MBR, VBR, $MFT, $LogFile
11. (non-volatile) Registry, Event Logs
12. (non-volatile) Shortcuts(LNKs), Jumplists
13. (non-volatile) SYSTEM32/drivers/etc files, systemprofile
14. (non-volatile) IE/Chrome/Firefox Artifacts
15. (non-volatile) Thumbcache*, Iconcache.db
15. (volatile) Packets (TBD)

::
:: Network Information
:: ---------------------------------------------------------
arp -a
netstat -nao
route PRINT
cports /stext
urlprotocolview /stext
net session
net file
net share
nbtstat -c
nbtstat -s
tcpvcon -a -c

::
:: Process Information
:: ---------------------------------------------------------
pslist /accepteula
cprocess /stext
procinterrogate -ps
procinterrogate -list -md5 -ver -o
tasklist -V
tlist (-c | -t | -s)
listdlls /accepteula
dllexp /stext
injecteddll /stext
driverview /stext
handle /accepteula
openfilesview /stext

::
:: User Logon Information
:: ---------------------------------------------------------
psloggedon /accepteula
logonsessions /accepteula
netusers /local /history
net user
winlogonview /stext

::
:: System Information
:: ---------------------------------------------------------
psinfo /accepteula
psinfo (-d | -s | -h)
wul /stext
gplist
gpresult /Z
psservice /accepteula
turnedontimesview /stext
lastactivityview /stext
mylastsearch /stext

::
:: Network Interface Information
:: ---------------------------------------------------------
promiscdetect
ipconfig /all
ipconfig /displaydns
getmac
networkinterfacesview /stext

::
:: Password Information
:: ---------------------------------------------------------
mailpv /stext
bulletspassview /stext
netpass /stext
webbrowserpassview /stext
wirelesskeyview /stext
rdpv /stext

::
:: MISCs Information
:: ---------------------------------------------------------
at
schtasks /query /fo list /v
pclip
autorunsc /accepteula