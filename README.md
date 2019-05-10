# INFORMASJONSSIKKERHET - TK2100
## OVERDNET
-----------
### Hvordan oppnå stabile systemer?
- Policy(retningslinjer) er grunnlaget for et stabilt system
  - En beslutning om hva vi ønsker oss, hvordan det skal være, sett i sammenheng med hva vi har råd til
- Forutsigbarhet: 
  - Det viktigste målet er et forutsigbart system. Det gir pålitelighet, tillit og dermed sikkerhet
- Skalerbarhet: 
  - Systemet skal vokse i tråd med policy og fungere forutsigbart m.a.o sikkert
--------------
### Designprinsipper
- Design bør være offentlig og ikke basert på at ingen vet hvordan systemet er implementert. 
- Standard bør være ingen har tilgang og dermed må gis tilgang til objekter i systemet eksplisitt
- Hver prosess bør ha færrest mulig privilegier
- KISS(Keep it simple,stupid): Kompleksitet er sikkerhetens ende. Hvis det er vanskelig å forstå et system, er det vanskelig å avgjøre om det er sikkert.
---------
### CIA - modellen
#### C: Confidentiality: å unngå uautorisert tilgengeligjøring av informasjon
- Viktige verktøy:
  - Kryptering - gjøre data "ugjenkjennelig/uleselig" for uvedkommende
    - Krypteringsnøkler
  - Adgangskontroll: Regler og retningslinjer som begrenser adgang til konfidensiell informasjon
  - Autentisering - Bekrefte at brukeren som skal ha tilgang er rett person
    - Passord 
    - Nøkkelkort 
    - Biometrisk id osv.
    - To-faktor autentisering
  - Autorisering - Å bestemme hvilke ressurser en person/system skal ha tilgang på basert på adgangs-retningslinjene
  - Fysisk sikring - Fysiske barrierer som hindrer uatoriserte personer fra å få tilgang til dataene.
    - Låste dører
    - Vakter
    - Plassere servere på et sikkert sted
    - Farraday-bur(isolasjon fra radiobølger)
#### I: Integrity: Se til at informasjon ikke blir endret på en uatorisert måte
- Viktige verktøy:
  - Backup - å ha kopi av data på et trygt sted. F.eks annen geografisk lokasjon
  - Sjekksummer - Er dataene som ble lagret den samme som nå ligger på server? Små endringer vil føre til en endre sjekksum
  - Versjonskontroll - gjøre det mulig å rulle tilbake feil som er gjort ved autoriserte og uatoriserte endringer
#### A: Availability: At informasjon er tilgjengelig og mulig å endre innenfor rimelig tid av de som er autorisert til det
- Viktige verktøy:
  - Vedlikehold av hardware
  - Kontinuerlig oppgradering hardware og software
  - Kontinuitetsplaner ved nedetid - er data tilgjengelig selv om systemene går ned?
  - Separat server med backup(mirror image) som kan tas i bruk ved nedetid
--------
### AAA - Assurance, Authenticity, Anonymity
#### Assurance: Handler om hvordan tillit etableres og håndteres i systemet
- Retningslinjer(Policies): Spesifiserer forventet adferd av brukerne og systemene
- Tillatelser(Permissions): Beskriver hva slags adferd som er tillat for de som benytter systemet eller samhandler med personer
- Beskyttelsesmekanismer: Beskriver hvilke mekanismer som benyttes for å håndheve retningslinjene og tillatelsene
#### Authenticity: Er evnen til å fastslå om utsagn, retningslinjer og tillatelser gitt av en person/et system er ekte(ikke forfalsket)
- Viktige verktøy: 
  - Digitale signaturer: Benyttes f.eks for å bekrefte autensiteten til nettsider 
#### Anonymity: At enkelte transaksjoner eller lagrede data kan føres tilbake til enkeltpersoner.
- Viktige verktøy:
  - Aggregering: kombinere individuelle data/spor på en slik måte at publiserte data ikke kan føres tilbake til enkeltperson
  - Mixing: Blande sammen attributter slik at "fiktive personer" oppstår
  - Proxyer: la noen/systemer handle på vegne av ekte personer på en måte som ikke lar seg spore
  - Pseudonym: fiktiv identitet der ekte kun er kjent av systemet 
---------
### Alternativer til CIA-modellen
#### IAM - modellen [Integrated assessment modelling - Wikipedia](https://en.wikipedia.org/wiki/Integrated_assessment_modelling)
---------
### Teknikker for adgangsbegrensning
#### ACL - Access control list: [Access-control list - Wikipedia](https://en.wikipedia.org/wiki/Access-control_list)
- Spesifiserer hvilke brukere som har tilgang til hvilke objekter i et "computer file system" i tillegg til hvilke operasjoner som er loving på de gitte objektene.
- Definerer hvert objekt o, en liste L, som kalles o's access control list. Den lister opp for alle brukere/prosesser om og hvilke rettigheter de har på objektet. 
- Typisk definert slik på et objekt: (Alice: read,write; Bob: read)
#### ACM - access control matrix: [Access Control Matrix - Wikipedia](https://en.wikipedia.org/wiki/Access_Control_Matrix)
- En tabell som definerer tilgangsrettigheter
- Hver rad er en bruker og cellene i hver kolonne definerer adgangsrettigheter for ulike filer, mapper, ressurser
#### Capabilities: [Capability-based security - Wikipedia](https://en.wikipedia.org/wiki/Capability-based_security)
- Spesifiserer for hver  bruker/prosess hvilke ressurser den har adgang til og hvilke rettigheter den har 
#### Role-based access control [Role-based access control - Wikipedia](https://en.wikipedia.org/wiki/Role-based_access_control)
- Definerer roller og spesifiserer adgangsrettigheter basert på roller istedet for enkeltbrukere direkte
-------------
## KRYPTERING
------------
### Symmetrisk kryptosystem
- Alice og Bob har på forhånd blitt enig om en felles symmetrisk krypteringsmetode og en krypteringsnøkkel(K) for å sende klartekst(P) som de deretter kryptere/dekryptere til/fra chipertexten(C).
- Notasjon:
  - Rentekst(P)
  - Hemmelig nøkkel(K)
  - Krypteringsfunksjon(E<sub>k</sub>(`P`))
  - Dekrypteringsfunksjon(D<sub>k</sub>(`C`))
- Klartekst er typisk like lang som kryptogrammet
- Effektivitet:
- Metodene E<sub>k</sub> og D<sub>k</sub> bør ha effektive algoritmer i form av regnetid og minneplass
#### Trusselbilde
##### Angriper kan benytte følgende teknikker for å knekke et symmetrisk kryptosystem:
  - Samling av kryptogram(Chipertext only attack)
  - Samling av klartekst/kryptogram par(known plaintext attack)
  - Samling av klartekst/kryptogram par for klartekster valgt av angriper(chosen plaintext attack)
  - Samling av klartekst/kryptogram par for kryptogram valgt av angriper(chosen ciphertext attack)
##### Brute-force attack
- Vil si å prøve alle mulige nøkler K og sjekke om D<sub>k</sub>(`C`) ser ut som en sannsynlig klartekst
- Hvis krypteringsnøkkelen K er lang og tilfeldig nok vil dette være umulig å gjennomføre
------------
### Entropi i krypto
- Sier noe om hvor tilfeldig et kryptogram har mulighet til å være. Hvis angriper f.eks vet at renteksten P er skrevet på norsk vil teksten ha en viss entropi =  2<sup>1.3t</sup>
----------------
### Substitusjonschiffer: Å bytte ut et tegn med et annet
- Hver bokstav erstattes av en annen
- Er den enkleste form for kryptering
- Populær versjon er ROT13. Som vil si å forskyve alfabetet og benytte bokstaven 13 plasser opp.
![Capture.PNG](:storage\e694cb17-9f8c-44ff-ba94-cb06359a0701\a6be1bd9.PNG)

#### Frekvensanalyse: Benyttes ofte i angrep på substitusjonsmetoder
- Kjennskap til hvor ofte enkeltbokstaver, par og tripler vanligvis opptrer.
- Benyttes ofte i angrep på substitusjonsmetoder for å gjette seg til bokstaver og sammensetninger av disse i en kryptert tekst
![Capture1.PNG](:storage\e694cb17-9f8c-44ff-ba94-cb06359a0701\da4a049c.PNG) 
----------------
### Skinnechiffer
- Alternativ til substitusjon
- Basert på å endre rekkefølgen på en tekst ved hjelp av såkalte "skinner"
![Captur2e.PNG](:storage\e694cb17-9f8c-44ff-ba94-cb06359a0701\fe53e424.PNG)

### S-bokser
- Substitusjon gjøre på binære tall 
- Erstatter ved oppslag nibble for nibble av rentekst P
### Vigenére chiffer [Vigenère cipher - Wikipedia](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
### One-time pads(engangsblokker) [One-time pad - Wikipedia](https://en.wikipedia.org/wiki/One-time_pad)
- I prinsippet umulig å knekke
- Oppfunnet i 1917 av Joseph Mauborogne og Gilbert Vernam
- Benytter en tabell med med shift-nøkler til å kryptere en rentekst M, med lengden n, der hver shiftnøkkel er valgt fullstendig tilfeldig.
- Bokstaver er ofte erstattet med tall slik at engangsblokken kan legges sammen med renteksten ved hjelp av tall. Deretter kjøres en mod 26 på tallene og gjør svaret om til bokstavene som tilsvarer tallene som kom ut på andre siden.
![Capture22.PNG](:storage\e694cb17-9f8c-44ff-ba94-cb06359a0701\4a5cbe8e.PNG) 

#### Svakheter ved engangsblokker
- Nøkkelen må være like lang som klarteksten 
- Nøkler må aldri gjenbrukes da det gjør dem veldig sårbare for å bli knekt av uvedkommende som ønsker å lese kryptogrammet
-------------------

### Blokk chiffer
- En klartekst med lengden n deles opp i en sekvens av m blokker.
- Hver melding krypteres og dekrypteres blokkvis
- Må ofte paddes på slutten for å oppnå like store blokker

#### Padding
Padding skal gjøre klarteksten like lang som nærmeste multippel av b. 
![6e05ded3.png](:storage\e694cb17-9f8c-44ff-ba94-cb06359a0701\6e05ded3.png)
#### Blokk chiffer i praksis
- DES: Data Encryption System. 
  - Utviklet at IBM og tatt i bruk av NIST(National Institute of standards and Technology)
  - 64-bit blokk. 56-bit nøkler
- 3DES 
  - Nøstet DES med tre forskjellige nøkler K<sub>A</sub>, K<sub>B</sub>, K<sub>C</sub>
- AES: Advanced Encryption System
  - Valgt av NIST i 2001 i en åpen konkurranse
  - 128-bit blokker og flere nøkkellengder: 128,192 og 256 bits
  - Ikke mulig å knekke med dagens teknologi
  - AES-256 er i dag den foretrukne symmetriske kryptertingsmetoden
------------------
### AES - Advanced Encryption System
- Er en form for blokk chiffer
- 128 bit blokker
- Finnes i ulike versjoner: AES-128, AES-192 og AES-256
- AES-256 er den foretrukne versjonen da den har størst nøkkellengde
![Skjermb2ilde.PNG](:storage\e694cb17-9f8c-44ff-ba94-cb06359a0701\96d403d2.PNG)
#### Blokkchiffer og ulike modus
- Blokkchiffer kan kjøres i ulike modus. Forskjellen på disse er i hvilke rekkefølge krypteringen og dekrypteringen gjennomføres
- AES og andre blokkchiffer kan kjøres i ulike modus. Det enkleste er ECB(Electronic Code Book) en annen type er CBC(Chipher Block Chaining)
##### ECB - Styrker og svakheter
- Styrker:
  - Enkelt å gjennomføre
  - Tillater parall kryptering/dekryptering av blokker
  - Tapstolerant fordi hver enkelt blokk dekrypteres for seg
- Svakheter:
  - Noen dokumentformater og bilder egner seg ikke da den krypterte teksten fortsatt vil vise mye av klarteksten
  ![Skjermbi2lde.PNG](:storage\e694cb17-9f8c-44ff-ba94-cb06359a0701\bf64bed7.PNG)
  
##### CBC - Cipher Block Chaining
- Forrige blokk kombineres med neste klartekst-blokk
- Styrker:
  - Avslører ikke mønstre i klarteksten
  - En den vanligst brukte
  - Relativ rask og enkel
- Svakheter
  - Krever pålitelig overføring da dekryptering er avhengig av at all data kommer frem i riktig rekkefølge
----------------
### EFS - Windows File Encryption System
- Innebygget kryptering i windows
- Bruker AES som default, men kan også benytte 3DES og DESX.
- Beskytter ikke hvis et program er logget inn med rettigheter til å lese
---------------
### Stream cipher [Stream cipher - Wikipedia](https://en.wikipedia.org/wiki/Stream_cipher)
- Ingen praktisk grunn til å benytte dette, bruk blokk cipher istedet.
- Egnet for uforutsigbar lengde på data
- Vanlig stream-cipher er "RC4"
-----------
### Public Key kryptering - Asymmetrisk kryptering
- Benytter enveisfunksjoner Exempel: f(x)=(x^173)mod65537 (?)
- Kjent som: diskret logaritme problemet da det vil være neste umulig å finne eks basert på informasjonen som ligger offentlig tilgjengelig for kryptering
#### Primtall 
- Public key kryptering bygger på noen egenskaper ved primtall
- Den felles kunnskapen/nøkkelen er i bunn og grunn tallteori (primtall), og det er vanskelig/kostbart og tidkrevende å faktoriserestore tall
- Det finnes ca 4 M primtall under 10 G, og de blir stadig sjeldnere for større tall (så langt...)

#### Diffie-hellman nøkkelutveksling [YouTube](https://www.youtube.com/watch?v=NmM9HA2MQGI)
![Skjermbil22de.PNG](:storage\e694cb17-9f8c-44ff-ba94-cb06359a0701\65f567a6.PNG)
- Diffie-Hellman utveksler (symmetriske) nøkler med private/public nøkler, men det er ikke noe kryptering
- Publisert i 1976
- Basert på lignende nøkkelpar som RSA, men inneholder ingen form for kryptering. Er kun benyttet til å utveksle en hemmelig krypteringsnøkkel som deretter kan benyttes til å kryptere meldingen man ønsker å sende. 
--------------
### RSA
- Blir brukt i assymetrisk kryptering.
- Bruker en public key og en private key til for kryptering og dekryptering av informasjon
- Benyttes også til å signere data slik at man kan være sikker på at informasjonen som ble sendt kom fra rett person.
  - Hvis jeg krypterer meldingen min med min "secret key" og deretter med din public key vil du kunne dekryptere meldingen ved hjelp av din secret key og min public key. Du har dermed fått bekreftet at meldingen faktisk kom fra meg så lenge ingen har stjålet min secret key. 
  - The RSA algorithm involves four steps: key generation, key distribution, encryption and decryption.
#### Hvor trygt er egentlig RSA?
- RSA-768 –ansett som brutt
- RSA-1024 – ansett som at den KAN knekkes av nation state attacker
- RSA-4096 –standard i dag, kan ikke knekkes
- RSA-8196 –«Future proof»

### SSL/TLS
- Benytter følgende algoritmer: RSA, Diffie-Hellman, ECC (eller SRP, PSK)
- Autentisering gjøres med asymmetrisk algoritme(RSA, ECC eller DSA)
- Kryptering av data med symmetrisk nøkkel AES(eller RC4, 3DES, Camellia, RC2, IDEA)
- Mest grunnleggende angrep er ”downgrade” attacks, hvor MITM lurer hver side til å bruke en svak nøkkel (for eksempel eNULL cipher)

### Signaturer, sjekksummer og hashfunksjonen

#### Hashfunksjoner
- En hashfunksjon endrer en klartekst P til en verdi x = h(P) med en forhåndsbestemt lengde som kalles hashverdien av P.
- En såkalt kollisjon i hash-sammenheng er når to klartekster P og Q får samme hashverdi h(P) = h(Q)
#### Kryptografiske hashfunksjoner
- Er enveisfunksjoner
- Er kollisjonsresistente i motsetning til andre hashfunksjoner
- Hashverdien anbefales å være minimum 256 bit for å beskytte mot brute-force generering
##### Bruksområder krypto-hashfunksjoner
- Verifisere at en fil ikke er blitt endret på veien
  - Signering av drivere
  - Signering av installasjonefiler
##### MD5 (Message-digest Algorithm)
- 128-bits hash verdier
- Fremdelse mye bruk selv om den regnes som usikker
  - Chosen prefix attack

##### SHA (Secure hash algorithm)
- Utviklet av NSA og godkjent av NIST
- Ulike typer:
  - SHA-0 og 1
    - 160 bit
    - Regnes som usikker
    - Mindre sårbar enn MD5
  - SHA-2
    - 256 bits og 512 bits
    - Finnes publiserte angrepsteknikker, men regnes fremdeles som sikker
  - SHA-3
    - Var et resultat av en offentlig konkurranse i 2007
    - Keccak algoritmen ble vinneren, men noen tror NSA har vært inne og lagt inn bakdører i algoritmen og brukes ikke fordi mange tror den ikke er sikker pga. dette


## OPERATIVSYSTEM
Se også forelesningsslides om OS fra høsten 2018

### ACL'er (Access Control Lists)
- Beskytte minne og filsystem mot uatoriserte endringer
#### Linux/OSX vs NT
- Linux/OSX:
  - Bruker Tillat-bare ACE
  - Tilgang gis av ACL for fil og alle foreldre kataloger
  - Alle kataloger må ha execute-bit satt(cd)
- NT
  - Bruker både allow og deny ACE
  - deny går foran allow
  - Tilgang avhenger kun av filen ACL
  - Tilgang arves vanligvis fra katalog
  - Systemer holder oversikt over arvede ACLer

### Sikkerhet i Windows
- Isolering av priviligert kode på Ring 0
- Hver usermode prosess har separate minneområder
#### Split priviliges og UAC(Win)
- Er et problem at brukere alltid er logget in som administrator i windows og farlig kode dermed kan kjøres
- Løsningen på dette var å spørre brukeren hver gang kode skulle gjøres.  UAC(User account control)-popup som kjøres i Secure Desktop som brukeren må trykke ok på. Dette gjør dermed at farlig kode ikke kan kjøres uten at brukeren godkjenner det. 
- Microsoft skriver dermed fra seg ansvaret for at farlig programvare kjøres på brukerens pc fordi brukeren må godkjenne. Siden dette ofte popper opp blir mange brukere vant med å trykke allow på meldingen som kommer frem og er dermed ikke et veldig godt verktøy for å stoppe malware. 
#### Session 0 isolation(Win)
- Tidligere så kjørte første inloggede bruker på Session 0. Det var dermed lett å Hijacke tjenester som kjørte her. 
- I vista kom session 0 isolation som vil si at ingen brukere kjører på session 0
#### Protected mode (Win)
- Den mest sårbare applikasjonen i windows har vist seg å være internet explorer
- Dette ble løst i vista ved å kjøre IE i protected mode
- Det vil si at den kjører på laveste integritetsnivå og får ikke lov til å gjøre endringer på maskinen
#### Windows firewall
- Filtrer all innkommende trafikk
- Mulighet for å konfigurere regler for utgående trafikk
- Svakheter:
  - har ikke håndtering av trojaner-teknikker
  - Regler kan legges til gjennom et COM-interface - av alle...
  - Regler ligger i plaintext i registry

#### Windows Defender
- Basert på GIANT AntiSpyware, men mye funksjonalitet ble fjernet av microsoft
- Preinstallert fra og med windows Vista
- Ikke en fullgod antivirus og må suppleres med dedikert antivirus
#### Kryptering i windows
- Encrypted file systemt (EFS)
- BitLocker disk encryption
  - Full volum kryptering
  - Bruker AES
  - Krevet boot passord for adgang til pc
  - Søtter også USB device med nøkkel på
#### Patch guard
- På x86 versjoner av Windoes er det mulig, fra en driver, å endre strukturen i Windows kernel direkte - dette kalles kernel patching
  - Benyttes primært av to grupper software: Rootkits og AntiVirys/Spyware
- på 64 bits windows beskytter patch guard kritiske deler av kernel. Ved å kalkulere sjekksum av minnet og krasje systemet hvis sjeksummen ikke stemmer
- Patchguard endres periodisk slik at det er vanskeligere å reverse engineere
### BUffer overflow attack
- Kode som skriver over minneadresser for å kjøre malicious kode. 
- ASLR(Adress space layout randomization) er en metode for å forhindre dette. Plasserer alle minneblokker tilfeldige steder i minnet slik at det er umulig å vite hvilke adresser man må overta for å få tilgang til kjørbar kode og root.
### Rootkits
- Tidligere: Verktøy brukt av en hacker for å skaffe seg rootaccesspå en UNIX server. Inneholdt også ofte mulighet til å slette logger for å skjule spor etter hackingen.
- I dag: Egentlig ikke en egen type malware, men en teknikk brukt av malwarefor å skjule sine spor og gjøre seg selv usynlig på maskinen som er infisert.
- Teknikker bruk av rootkits:
  - Skjuling av prosesser/drivere
  - Skjuling av registryoppføringer
  - Skjuling av fysiske filer på disk


## MALWARE
### Hva er malware?
- Malicious software
- Fellesbetegnelse for ondsinnet programvare som utfører uatoriserte og (oftest) skadelige handlinger

### Innside-angrep
- Skyldes en "utro tjener" i en organisasjon som tilrettelegger sikkerhethull slik at det er mulig å ta ibruk bakdører for å komme seg inn i systemet

#### Bakdør aka backdoor
- En skjul metode/kommando i et program som typusk tillater en bruker å utføre handlinger han/hun normalt ikke har tillatelse til
- Programmet oppfører seg vanligvis helt som forventet
- Når aktivert så gjør programmet noe du ikke forventet. f.eks hever privilegier
- Andre utgaver av dette kan være såkalte easter eggs som ikke er farlige

#### Logikkbomber
- Logikkbomber utfører en handling førs når en bestemt betingelse inntreffer
- Eksempel: En programmerer legger inn en betingelse om at programmet skal krasje og alt slettes dersom han ikker med i to lønnsutbetalinger på rad. 

#### Forsvar mot innside-angrep
- Unngå "single point of failure"
- Bruk manuell kode-gjennomgang
- Bruk arkiveringsverktøy og rapport-vertkøy
- Begrens tillatelser og autorisasjoner
- Fysisk sinkring av kritiske systemer 
- OVervåk ansattes adferd
- Har full kontroll på alt som installeres på organisasjonens systemer

### Klassifikasjon
- Malware kan deles opp i ulike typer ut fra hvordan de spres og hvordan de skjuler seg:
  - Spredning:
    - Virus: Virus endrer eksisterende filer og systemer, koden kan ikke leve eller spre seg alene
    - Orm: Automatisk spredning fra maskin til maskin over nettet
  - Skjuler seg:
    - Rootkit: endrer OS for å skjule nærvær
    - Trojaner: Nytteprogram som skjuler ondsinnede operasjoner (f.eks keylogger)
  - Nyttelast(payload):
    - Alt fra humor/irritasjon til ran av maskinkraft og identitetstyveri

### Virus
- Et program som kan replisere seg selv
  - Ved å endre andre filer/program ved å infisiere dem med kode som kan formere seg videre
- Det er evnene til å formere seg "LOKALT" som skiller virus fra andre typer malware
- Krever vanligvis innledende brukermedvirkning for å formere seg 

#### Tradisjonelle datavirus
- I dag er det mer vanlig med ormer og trojanere. Ondsinnede filer som er i stand til å leve et selvstendig liv uten en host-prosess
- Ormer har eksistert lengre enn PCer og første registrerte malware kom i 1971 og kalles "The Creeper program" og den spredde seg på ARPAnet
- Brain krediteres om verdens første "PC virus"(1986) og sener samme år klarte man for første gang å infisere exe filer med Suriv-02. Før dette var exe filer ansett som et trygt format fordi det var så komplekst at ingen ville kunne kare å infisere dem i motsetning til com filser som er ren maskinkode
##### Brain
- Skrevet av to pakistanske brødre for å beskytte mot ulovlig deling av programvare for hjerte-monitorering som de solgte.
- Spredde seg verden rund via disketter

#### Flere farlige virus som kom på sent på 80 og tidlig 90-tall
  - Jerusalem(1987) - Sletter filer på maskinen på fredag 13.
  - AIDS Trojan(1989) - krypterte hele disken din
  - Dark Avenger(1989) - Overskrev tilfeldige deler av disken 1/16 ganger viruset kjørte 
  - Tequila(1991) - Polymorph virus som var skjult og veldig vanskelig å oppdage

#### Virus: Livsfaser
- Dvale-fasen
  - Offeret er infisert, men visruset ligger lavt og unngår å bli oppdaget
- Spredningsfasen
  - Viruset repliserer seg selv, og infiserer flere filer (og nye systemer)
- Avtrekker-fasen
  - En logisk betingelse(Avtrekker) får viruset til å begynne å utføre sin intenderte handling
- Aksjons-fasen
  - Viruset utfører handlingen det var designet  for

#### Infeksjonstyper
- Overskriving
  - Ødelegger opprinnelig kode
- Pre-pending
  - Beholder opprinnelig kode
  - Kan komprimere den
- Biblioteksinfeksjon
  - Tillater virus å være minne-resistente
  - F.eks kernel32.dll
- Makro-virus
  - MS office dokumenter
  - Erstatter gjerne hoveddokument-malen
#### Dynamic Link Library aka DLL
- DLLer har en export-tabell med liste over metoder(systemkall) og adressen de ligger på
- Mange virus enten derer tabellen slik at den kaller virusets kode i stedet, eller legger inn ondsinnet kode i selve DLLen
- Typisk offer: kernel32.dll, ntdll.dll, kernelbas.dll (65bit)


#### Hvordan oppdage virus?
- Se etter signatuirer fra kjente virus og søke etter disse
  - Forutsetter at man finner karakteristiske kodesnutter i viruset som man så kan sette opp antivirus-programmet itl å søke etter
  - Programmet legget deretter i karantene
- Problemet i dag er at det kommer så mange nye virus hver dag (375000)
- Alle antivirs selskaper deler databaser over kjente virus
- I tilleg kan m,an kjøde feeds fra forsknings institutter (Virus total, AV test, VB)
- Alle filer fra kjente feeder blir lagt inn i virusdatabasen som en checksum

#### Teknikker for å gjemme seg
- Krypterte virus
- Polymorfe virus
  - Tilfeldige variasjoner legges inn i koden hele tiden slik at signaturen endrer seg
- Metamorfe virus
  - Forsøker å gjemme seg og være vanskelige å finne signatur på ved "obskurifisering"
    - Emdre rekkefølgen på instruksjoner
    - Legge inn unyttinge intruksjoner
    - Omstrukturere indre metode-kall
- Å gjemme seg handler som regel om å skjule signaturen til viruset godt


### Ormer
