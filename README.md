# TrailHunter

**Platformă DFIR pentru detecția și corelarea atacurilor multi-stadiu pe Windows.**

## Problema

Răspunsul la incidente de securitate pe sisteme Windows se confruntă cu o dublă provocare:

- **Volatilitatea dovezilor digitale** — datele relevante dispar la oprirea sistemului.
- **Fragmentarea telemetriei** în surse eterogene: Sysmon, Windows Security & System Logs, PowerShell Script Block Logging, Registry, Task Scheduler, WMI — fiecare cu propriul format și propriile convenții de denumire.

Pe un sistem activ, volumul de evenimente generat poate depăși **zeci de mii de intrări pe oră**. În absența unui mecanism automat de normalizare și corelare, investigatorul reconstruiește manual scenariul de atac — un proces lent și predispus la omisiuni, în special în atacurile multi-stadiu.

## Soluția

TrailHunter este construit pe o arhitectură **client-server** cu trei componente principale:

| Componentă | Rol |
|---|---|
| **Sondă** (PowerShell + FastAPI) | Colectează artefacte direct de pe sistemul investigat, fără dependențe instalate |
| **Server de analiză** (Python) | Normalizează, detectează și corelează evenimentele |
| **Frontend** (React + Cytoscape.js) | Expune rezultatele investigatorului sub formă de graf interactiv |

Separarea responsabilităților menține sonda ușoară pe sistemul investigat, în timp ce întreaga logică de analiză este centralizată pe server.

<p align="center">
  <img src="assets/architecture-overview.jpg" alt="Arhitectura generală TrailHunter" width="800">
</p>

### Colectarea probelor

Sonda colectează artefacte din **șase module de telemetrie**, prin două metode de deployment:

- **Hardware** — printr-un dispozitiv Raspberry Pi Zero 2W configurat simultan ca Human Interface Device și interfață de rețea peste USB.
- **Software** — prin SSH sau WinRM, prin apelarea endpoint-ului de către investigator.

Fiecare sursă este însoțită de un hash **SHA-256**, garantând integritatea probelor și un lanț de custodie verificabil.

## Pipeline de analiză

Pe serverul de analiză, datele parcurg patru straturi succesive:

1. **Normalizare** — evenimentele sunt aduse la un model canonic conform **Elastic Common Schema (ECS)**.
2. **Detecție** — un motor bazat pe reguli, mapate pe tehnicile **MITRE ATT&CK** și pe fazele **Cyber Kill Chain**, identifică activitate suspectă.
3. **Fuzionare** — elimină redundanțele generate de observarea aceluiași eveniment din surse diferite.
4. **Corelare** — construiește un graf orientat pe baza contractelor de capabilități **requires/provides**, a genealogiei proceselor și a agregării identității operaționale (SID, logon ID, IP sursă).

<p align="center">
  <img src="assets/pipeline.jpg" alt="Pipeline-ul de analiză TrailHunter" width="850">
</p>

### Output-ul final

Rezultatul este vizualizat interactiv prin **Cytoscape.js**, stratificat pe fazele Kill Chain (axa verticală) și ordonat cronologic (axa orizontală), astfel încât progresia atacului poate fi citită de sus în jos.

## Încadrare în securitatea cibernetică

TrailHunter se situează în domeniul **DFIR** și al **threat hunting-ului**, integrând:

- Detecție bazată pe reguli
- Normalizare conformă cu standardul **ECS**
- Modelarea comportamentului adversarial prin **MITRE ATT&CK** și **Cyber Kill Chain**
- Asigurarea integrității criptografice a probelor digitale

Prin reconstrucția automată a scenariilor de atac multi-stadiu sub forma unui graf cauzal, proiectul contribuie la o direcție activă de cercetare în securitatea defensivă, oferind o alternativă lightweight și accesibilă la platformele enterprise (Velociraptor, KAPE, Elastic SIEM).

## Tech stack

`PowerShell` · `Python` · `FastAPI` · `Pydantic` · `NetworkX` · `React` · `TypeScript` · `Cytoscape.js` · `Raspberry Pi Zero 2W`

