# Mathdop - HackMyVM (Easy)

![Mathdop.png](Mathdop.png)

## Übersicht

*   **VM:** Mathdop
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Mathdop)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 23. April 2025
*   **Original-Writeup:** https://alientec1908.github.io/Mathdop_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Mathdop" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung einer Remote Code Execution (RCE)-Schwachstelle in einem Spring Cloud Skipper Server, der auf Port 7577 lief. Nach dem Hochladen eines präparierten Pakets wurde eine Reverse Shell als Benutzer `cnb` erlangt. Die erste Rechteausweitung zum Benutzer `mathlake` gelang durch das Knacken eines Passwort-Hashes, der durch Hinweise im System und Analyse einer Excel-Datei rekonstruiert werden konnte. Die finale Eskalation zu Root erfolgte durch Ausnutzung einer unsicheren `sudo`-Regel, die `mathlake` erlaubte, ein Bash-Skript (`/opt/secure_input_handler.sh`) auszuführen, welches durch eine Schwachstelle in der Eingabeverarbeitung das Auslesen der `/etc/shadow`-Datei ermöglichte. Der Root-Passwort-Hash konnte anschließend geknackt werden.

*Hinweis: Im Original-Writeup wurde auch ein SUID-`wget`-Exploit als alternativer Weg zum Root-Zugriff als `cnb` gezeigt, der hier der Vollständigkeit halber erwähnt wird, aber nicht der Hauptpfad des Berichts war.*

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `grep`
*   `awk`
*   `nmap`
*   `curl`
*   `ffuf`
*   `git`
*   `javac`
*   `jar`
*   `python3 http.server`
*   `nc` (netcat)
*   `gobuster`
*   `feroxbuster`
*   `java`
*   `hydra`
*   `ssh`
*   `sudo`
*   `base64`
*   `john`
*   `su`
*   `find`
*   `wget`
*   `chmod`
*   `zsteg`
*   `unzip`
*   `tr`
*   `col`
*   `sed`
*   `timeout`
*   `bash`
*   `crunch`
*   Standard Linux-Befehle (`id`, `ls`, `cat`, `cp`, `mv`, `mkdir`, `cd`, `ll`, `df`, `env`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Mathdop" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.183) mit `arp-scan` identifiziert.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 7.4), Port 7577 (HTTP, Apache Tomcat / Spring Cloud Skipper) und Port 9393 (HTTP, Apache Tomcat / Spring Cloud Data Flow Server).
    *   Enumeration von `/api/about` auf Port 7577 enthüllte "Spring Cloud Skipper Server 2.11.3-SNAPSHOT".
    *   Enumeration von `/management/info` auf Port 9393 enthüllte "Spring Cloud Data Flow Server 2.11.3-SNAPSHOT".

2.  **Initial Access (RCE via Spring Cloud Skipper/Data Flow als `cnb`):**
    *   Recherche nach Schwachstellen für Spring Cloud Skipper/Data Flow 2.11.3-SNAPSHOT führte zu CVE-2024-37084 (RCE).
    *   Ein öffentlicher PoC (`CVE-2024-37084-Poc.py`) wurde von GitHub geklont.
    *   Ein Java-Reverse-Shell-Payload (`Exploit.java`) wurde erstellt, kompiliert (`javac`) und als `payload.jar` verpackt (`jar`).
    *   Die `payload.jar` wurde über einen Python-HTTP-Server bereitgestellt. (Alternative: `beans.xml` für `ClassPathXmlApplicationContext` Exploit).
    *   Nach mehreren fehlgeschlagenen Versuchen mit JNDI/LDAP und dem ursprünglichen Exploit-Skript auf Port 7577, wurde ein modifiziertes Exploit-Skript (das `beans.xml` nutzt) erfolgreich gegen Port 7577 (oder implizit Port 9393, da beide die gleiche Version hatten) ausgeführt.
    *   Dies löste das Herunterladen und Ausführen der `beans.xml` (welche `java.lang.ProcessBuilder` für eine Reverse Shell nutzte) auf dem Zielserver aus.
    *   Eine Reverse Shell als Benutzer `cnb` wurde auf einem Netcat-Listener empfangen.

3.  **Privilege Escalation (von `cnb` zu `mathlake`):**
    *   Im Home-Verzeichnis von `cnb` wurde eine `note` (E-Mail-Text) gefunden, die Hinweise auf ein Passwort für `mathlake` enthielt (SHA-256, 3 Variablen, Zieldatum Juni 2025).
    *   Als `root` (nach späterer Eskalation) wurden Dateien in `/var/mail/mathlake` gefunden: `data.xlsx`, `test.png`, `true.png`. Diese wurden exfiltriert.
    *   `data.xlsx` enthielt Verkaufsdaten. Durch Extrapolation dieser Daten und Analyse der Hinweise aus der `note` wurde eine Passwortgenerierungslogik rekonstruiert (String `i*j*k`, wobei `i` aus Extrapolation 56-59, `j` und `k` aus Quartalsindizes 0-3).
    *   Ein Python-Skript (oder Bash-Skript `fff.sh`) generierte 64 SHA-256 Hashes basierend auf dieser Logik.
    *   Mittels `hydra` wurde ein Brute-Force-Angriff auf den SSH-Dienst für den Benutzer `mathlake` mit der generierten Hash-Liste durchgeführt. Das Passwort (einer der Hashes: `9bd29d2c...`) wurde gefunden.
    *   Erfolgreicher SSH-Login als `mathlake`.

4.  **Privilege Escalation (von `mathlake` zu `root`):**
    *   `sudo -l` als `mathlake` zeigte, dass das Skript `/opt/secure_input_handler.sh` als `root` ohne Passwort ausgeführt werden durfte (`(ALL) NOPASSWD: /opt/secure_input_handler.sh`).
    *   Das Skript nahm Base64-kodierte Eingaben entgegen, filterte sie stark und führte sie mit `bash -c` aus, prüfte aber nur den Befehlsnamen gegen eine Whitelist (`date`, `pwd`, `echo`).
    *   Durch Übergabe von `date -f /etc/shadow` (Base64-kodiert) an das Skript konnte der Inhalt der `/etc/shadow`-Datei ausgelesen werden (da `date` ein erlaubter Befehl ist und `-f` als Argument durch den Filter kam).
    *   Ein Kommentar `# Worth waiting for` in der `/etc/shadow`-Datei wurde als Hinweis auf das Root-Passwort interpretiert.
    *   Der extrahierte `root`-Passwort-Hash (`$6$WUx...`) wurde mit `john` und `rockyou.txt` geknackt. Das Passwort war `Worth waiting for`.
    *   Mit `su root` und dem Passwort `Worth waiting for` wurde Root-Zugriff erlangt.
    *   Die User-Flag (`flag{d79b3daf297f1ad136284d93900c0fe8543a52eb}`) und Root-Flag (`flag{29975f78aafc266eaa88520357552917d1164964}`) wurden gefunden.

*Alternativer Privesc (cnb zu root): Ein SUID-gesetztes `/usr/local/bin/wget` wurde gefunden. Dies hätte zum Überschreiben von `/etc/passwd` genutzt werden können, um einen Root-Benutzer hinzuzufügen.*

## Wichtige Schwachstellen und Konzepte

*   **Spring Cloud Skipper/Data Flow RCE (CVE-2024-37084):** Eine Schwachstelle (wahrscheinlich unsichere YAML-Deserialisierung, die das Laden externer XML-Kontexte erlaubt) in der SNAPSHOT-Version ermöglichte Remote Code Execution.
*   **Passwort-Rekonstruktion aus Hinweisen:** Das Passwort für `mathlake` musste durch Interpretation von Hinweisen (E-Mail, Excel-Daten, SHA-256) und Generierung einer Passwortliste erraten werden.
*   **Unsichere `sudo`-Regel (Skript mit Filter-Bypass):** Ein Skript, das mit `sudo`-Rechten ausgeführt werden konnte, hatte eine fehlerhafte Eingabefilterung, die das Auslesen beliebiger Dateien über Argument-Injection in einen erlaubten Befehl (`date -f`) ermöglichte.
*   **Informationslecks:** Versionsinformationen (Spring Cloud SNAPSHOT), Kommentare in Systemdateien (Hinweis auf Root-Passwort).
*   **SUID `wget` (Alternativer Vektor):** Ein SUID-gesetztes `wget` hätte eine direkte Eskalation von `cnb` zu `root` ermöglicht.
*   **Steganographie (implizit):** Die PNG-Dateien in `/var/mail/mathlake` enthielten versteckte Audio-Daten (MP3, AAC), deren Inhalt für den Lösungsweg aber nicht entscheidend war.

## Flags

*   **User Flag (vermutlich `/home/mathlake/user.txt`):** `flag{d79b3daf297f1ad136284d93900c0fe8543a52eb}`
*   **Root Flag (`/root/r00...00t.txt`):** `flag{29975f78aafc266eaa88520357552917d1164964}`

## Tags

`HackMyVM`, `Mathdop`, `Easy`, `Spring Cloud RCE`, `CVE-2024-37084`, `Java Deserialization`, `Password Reconstruction`, `sudo Exploit`, `Argument Injection`, `SUID wget`, `Linux`, `Web`, `Privilege Escalation`, `Apache Tomcat`
