#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Auditoria Profesional de Red - Version PowerShell
    Metodologia: Pentester Senior

.NOTES
    Requisitos: nmap instalado y en el PATH
    Ejecutar como Administrador
    Uso: powershell -ExecutionPolicy Bypass -File .\escaner_pro.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function Write-Info  { param($msg) Write-Host "[+] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[!] $msg" -ForegroundColor Red }
function Write-Step  { param($msg) Write-Host "[+] $msg" -ForegroundColor Yellow }

function Write-Log {
    param([string]$texto = "")
    Add-Content -Path $script:LOGFILE -Value $texto -Encoding UTF8
}

function Write-Seccion {
    param([string]$titulo)
    Write-Step $titulo
    Write-Log ""
    Write-Log "--- $titulo ---"
}

function Invoke-Nmap {
    param([string[]]$Argumentos, [string]$Etiqueta = "")
    if ($Etiqueta) { Write-Log ""; Write-Log "[$Etiqueta]" }
    Write-Log ("$ nmap " + ($Argumentos -join " "))
    try {
        $salida = & nmap @Argumentos 2>&1 | Out-String
        Write-Log $salida
        return $salida
    } catch {
        Write-Warn "Error ejecutando nmap: $_"
        Write-Log "[!] Error: $_"
        return ""
    }
}

function Test-PuertoAbierto {
    param([string[]]$Hosts, [string]$Puerto)
    $args = $Hosts + @("-p", $Puerto, "--open", "-oG", "-")
    $salida = & nmap @args 2>&1 | Out-String
    return $salida -match "$Puerto/open"
}

# Prioriza adaptadores fisicos sobre VirtualBox/VMware
function Get-RedLocal {
    Write-Info "Detectando interfaz de red activa..."

    $candidatos = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            ($_.IPAddress -match "^192\.168\." -or
             $_.IPAddress -match "^10\." -or
             $_.IPAddress -match "^172\.(1[6-9]|2[0-9]|3[01])\.") -and
            $_.PrefixOrigin -ne "WellKnown"
        }

    $adaptador = $candidatos | Where-Object {
        $iface = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $iface) { return $false }
        $iface.InterfaceDescription -notmatch "VirtualBox|VMware|Hyper-V|vEthernet|Loopback|TAP|Bluetooth"
    } | Select-Object -First 1

    if (-not $adaptador) {
        $adaptador = $candidatos | Select-Object -First 1
    }

    if (-not $adaptador) {
        Write-Warn "No se pudo detectar una IP de red local valida."
        exit 1
    }

    $iface = Get-NetAdapter -InterfaceIndex $adaptador.InterfaceIndex -ErrorAction SilentlyContinue
    Write-Info "Adaptador seleccionado: $($iface.InterfaceDescription)"

    $o = $adaptador.IPAddress -split "\."
    return @{
        MiIP    = $adaptador.IPAddress
        Red     = "$($o[0]).$($o[1]).$($o[2]).0/24"
        Gateway = "$($o[0]).$($o[1]).$($o[2]).1"
    }
}

function Get-InfoAuditor {
    Write-Seccion "INFORMACION DEL EQUIPO AUDITOR"
    Write-Log "[Adaptadores de red activos]"
    ipconfig /all | Out-File -Append -FilePath $script:LOGFILE -Encoding UTF8
    Write-Log "`n[Tabla ARP local]"
    arp -a | Out-File -Append -FilePath $script:LOGFILE -Encoding UTF8
    Write-Log "`n[Tabla de rutas]"
    route print | Out-File -Append -FilePath $script:LOGFILE -Encoding UTF8
    Write-Log "`n[Conexiones activas y puertos en escucha]"
    netstat -ano | Out-File -Append -FilePath $script:LOGFILE -Encoding UTF8
}

function Invoke-Fase1 {
    param([string]$Red)
    Write-Seccion "FASE 1: DESCUBRIMIENTO DE HOSTS (ARP)"

    $hostsGrepable = Join-Path $env:TEMP "hosts_grepable_$PID.txt"
    Invoke-Nmap @("-sn", "-PR", $Red, "-oG", $hostsGrepable) -Etiqueta "ARP sweep" | Out-Null

    $hostsVivos = @()
    if (Test-Path $hostsGrepable) {
        Get-Content $hostsGrepable | Where-Object { $_ -match "\bUp\b" } | ForEach-Object {
            if ($_ -match "Host:\s+(\d+\.\d+\.\d+\.\d+)") { $hostsVivos += $Matches[1] }
        }
        Remove-Item $hostsGrepable -Force -ErrorAction SilentlyContinue
    }

    if ($script:MI_IP -notin $hostsVivos) { $hostsVivos += $script:MI_IP }

    Write-Ok "Hosts vivos encontrados: $($hostsVivos.Count)"
    Write-Log "`n[Hosts descubiertos]"
    $hostsVivos | ForEach-Object { Write-Log "  $_" }
    Write-Log "[+] Total: $($hostsVivos.Count) hosts"

    if ($hostsVivos.Count -eq 0) {
        Write-Warn "No se encontraron hosts vivos. Abortando."
        exit 1
    }
    return $hostsVivos
}

function Invoke-Fase2 {
    param([string[]]$Hosts)
    Write-Seccion "FASE 2: ESCANEO DE PUERTOS Y DETECCION DE OS"

    Invoke-Nmap ($Hosts + @("-T4", "-p-", "--min-rate", "500")) `
        -Etiqueta "Todos los puertos TCP"

    Invoke-Nmap ($Hosts + @("-O", "-sV", "--osscan-guess", "--open")) `
        -Etiqueta "Deteccion de OS y versiones de servicios"

    Invoke-Nmap ($Hosts + @("-sU", "-p", "53,67,123,137,161,500,1900,4500", "--open")) `
        -Etiqueta "UDP servicios criticos"
}

function Invoke-Fase3 {
    param([string[]]$Hosts, [string]$GatewayIP)
    Write-Seccion "FASE 3: ENUMERACION DIRIGIDA POR SERVICIO"

    Write-Info "Comprobando SMB (445)..."
    if (Test-PuertoAbierto $Hosts "445") {
        Invoke-Nmap ($Hosts + @("-p", "445", "--open", "--script",
            "smb2-security-mode,smb-security-mode,smb-vuln-ms17-010")) -Etiqueta "SMB"
    } else { Write-Log "[SMB] Sin puerto 445 abierto." }

    Write-Info "Comprobando HTTP/HTTPS..."
    if ((Test-PuertoAbierto $Hosts "80") -or (Test-PuertoAbierto $Hosts "443")) {
        Invoke-Nmap ($Hosts + @("-p", "80,443,8080,8443", "--open", "--script",
            "http-title,http-server-header,http-headers,http-auth-finder")) -Etiqueta "HTTP - Cabeceras"
        Invoke-Nmap ($Hosts + @("-p", "80,443", "--open", "--script",
            "http-slowloris-check,http-shellshock,http-csrf")) -Etiqueta "HTTP - Vulnerabilidades"
        Invoke-Nmap ($Hosts + @("-p", "80,443", "--open", "--script", "http-enum")) `
            -Etiqueta "HTTP - Directorios expuestos"
    } else { Write-Log "[HTTP/HTTPS] Sin servidores web." }

    Write-Info "Comprobando SSL/TLS (443)..."
    if (Test-PuertoAbierto $Hosts "443") {
        Invoke-Nmap ($Hosts + @("-p", "443,8443", "--open", "--script",
            "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle")) -Etiqueta "SSL/TLS"
    } else { Write-Log "[SSL/TLS] Sin HTTPS." }

    Write-Info "Analizando DNS en el gateway..."
    Invoke-Nmap @("-Pn", "-sU", "-p", "53", "--open",
        "--script", "dns-recursion,dns-cache-snoop", $GatewayIP) -Etiqueta "DNS Gateway"

    Write-Info "Comprobando SNMP (161)..."
    Invoke-Nmap ($Hosts + @("-sU", "-p", "161", "--open",
        "--script", "snmp-info,snmp-brute")) -Etiqueta "SNMP"

    Write-Info "Comprobando RDP (3389)..."
    if (Test-PuertoAbierto $Hosts "3389") {
        Invoke-Nmap ($Hosts + @("-p", "3389", "--open", "--script",
            "rdp-enum-encryption,rdp-vuln-ms12-020")) -Etiqueta "RDP"
    } else { Write-Log "[RDP] Sin RDP expuesto." }

    Write-Info "Comprobando SSH (22)..."
    if (Test-PuertoAbierto $Hosts "22") {
        Invoke-Nmap ($Hosts + @("-p", "22", "--open", "--script",
            "ssh-auth-methods,ssh2-enum-algos")) -Etiqueta "SSH"
    } else { Write-Log "[SSH] Sin SSH expuesto." }

    Write-Info "Comprobando FTP (21)..."
    if (Test-PuertoAbierto $Hosts "21") {
        Invoke-Nmap ($Hosts + @("-p", "21", "--open", "--script",
            "ftp-anon,ftp-syst")) -Etiqueta "FTP"
    } else { Write-Log "[FTP] Sin FTP expuesto." }

    Write-Info "Comprobando bases de datos..."
    Invoke-Nmap ($Hosts + @("-p", "3306,1433,5432,27017,6379,9200", "--open",
        "--script", "mysql-info,ms-sql-info,mongodb-info,redis-info")) -Etiqueta "Bases de datos"
}

function Invoke-Fase4 {
    param([string[]]$Hosts)
    Write-Seccion "FASE 4: CREDENCIALES POR DEFECTO"

    Write-Info "Comprobando paneles HTTP con credenciales por defecto..."
    Invoke-Nmap ($Hosts + @("-p", "80,443,8080,8443", "--open",
        "--script", "http-default-accounts")) `
        -Etiqueta "HTTP - Paneles por defecto"

    Write-Info "Comprobando FTP anonimo y credenciales debiles..."
    if (Test-PuertoAbierto $Hosts "21") {
        Invoke-Nmap ($Hosts + @("-p", "21", "--open",
            "--script", "ftp-anon,ftp-brute")) `
            -Etiqueta "FTP - Acceso anonimo y brute"
    } else { Write-Log "[FTP] Sin FTP expuesto." }

    Write-Info "Comprobando SSH con credenciales comunes..."
    if (Test-PuertoAbierto $Hosts "22") {
        Invoke-Nmap ($Hosts + @("-p", "22", "--open",
            "--script", "ssh-brute")) `
            -Etiqueta "SSH - Credenciales comunes"
    } else { Write-Log "[SSH] Sin SSH expuesto." }

    Write-Info "Comprobando comunidades SNMP por defecto..."
    Invoke-Nmap ($Hosts + @("-sU", "-p", "161", "--open",
        "--script", "snmp-brute")) `
        -Etiqueta "SNMP - Comunidades por defecto"

    Write-Info "Comprobando bases de datos sin autenticacion..."
    Invoke-Nmap ($Hosts + @("-p", "3306,1433", "--open",
        "--script", "mysql-empty-password,ms-sql-empty-password")) `
        -Etiqueta "BBDD - Acceso sin autenticacion"

    Write-Ok "Fase 4 completada."
}

function Invoke-Fase5 {
    param([string[]]$Hosts, [string]$GatewayIP)
    Write-Seccion "FASE 5: ANALISIS DE VULNERABILIDADES"

    # ------------------------------------------------------------------
    # 5.1 CATEGORIA VULN COMPLETA DE NMAP
    # Lanza todos los scripts NSE de la categoria "vuln" contra los hosts
    # Detecta CVEs conocidos segun version de servicio detectada en Fase 2
    # ------------------------------------------------------------------
    Write-Info "Ejecutando categoria completa de vulnerabilidades (vuln)..."
    Invoke-Nmap ($Hosts + @("-sV", "--script", "vuln", "--open")) `
        -Etiqueta "Categoria vuln completa"

    # ------------------------------------------------------------------
    # 5.2 SMB - VULNERABILIDADES CRITICAS
    # MS17-010             : EternalBlue - RCE sin autenticacion (WannaCry/NotPetya)
    # MS08-067             : RCE critico en Windows XP/2003
    # smb-vuln-cve2009-3103: DoS en SMB2 (Vista/2008)
    # smb-double-pulsar    : Backdoor DoublePulsar (NSA leak)
    # smb-vuln-regsvc-dos  : DoS via registro remoto
    # ------------------------------------------------------------------
    Write-Info "Analizando vulnerabilidades criticas SMB..."
    if (Test-PuertoAbierto $Hosts "445") {
        Invoke-Nmap ($Hosts + @("-p", "445", "--open", "--script",
            "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve2009-3103,smb-double-pulsar-backdoor,smb-vuln-regsvc-dos")) `
            -Etiqueta "SMB - EternalBlue, MS08-067, DoublePulsar"
    } else { Write-Log "[SMB Vuln] Sin puerto 445 abierto." }

    # ------------------------------------------------------------------
    # 5.3 HTTP - VULNERABILIDADES WEB
    # http-shellshock         : Shellshock en CGI (CVE-2014-6271)
    # http-slowloris-check    : DoS Slowloris
    # http-csrf               : Formularios sin proteccion CSRF
    # http-dombased-xss       : XSS basado en DOM
    # http-stored-xss         : XSS persistente
    # http-fileupload-exploiter: Subida de ficheros sin restriccion
    # http-phpmyadmin-dir     : phpMyAdmin expuesto
    # http-vuln-cve2017-5638  : Apache Struts RCE (CVE-2017-5638)
    # http-vuln-cve2014-8877  : WordPress RCE
    # http-backup-finder      : Ficheros de backup expuestos (.bak, .old)
    # http-config-backup      : Ficheros de configuracion expuestos
    # http-git                : Repositorio .git expuesto publicamente
    # ------------------------------------------------------------------
    Write-Info "Analizando vulnerabilidades web HTTP..."
    if ((Test-PuertoAbierto $Hosts "80") -or (Test-PuertoAbierto $Hosts "443")) {
        Invoke-Nmap ($Hosts + @("-p", "80,443,8080,8443", "--open", "--script",
            "http-shellshock,http-slowloris-check,http-csrf,http-dombased-xss,http-stored-xss")) `
            -Etiqueta "HTTP - XSS, CSRF, Shellshock, Slowloris"

        Invoke-Nmap ($Hosts + @("-p", "80,443,8080,8443", "--open", "--script",
            "http-fileupload-exploiter,http-phpmyadmin-dir,http-vuln-cve2017-5638,http-vuln-cve2014-8877")) `
            -Etiqueta "HTTP - RCE, subida ficheros, phpMyAdmin, Struts"

        Invoke-Nmap ($Hosts + @("-p", "80,443,8080,8443", "--open", "--script",
            "http-backup-finder,http-config-backup,http-git,http-svn-enum")) `
            -Etiqueta "HTTP - Backups, Git/SVN expuestos"
    } else { Write-Log "[HTTP Vuln] Sin servidores web detectados." }

    # ------------------------------------------------------------------
    # 5.4 SSL/TLS - VULNERABILIDADES DE CIFRADO
    # ssl-heartbleed   : Heartbleed (CVE-2014-0160) - fuga de memoria OpenSSL
    # ssl-poodle       : POODLE (CVE-2014-3566) - downgrade a SSLv3
    # ssl-ccs-injection: CCS Injection (CVE-2014-0224)
    # ssl-dh-params    : Logjam/FREAK - parametros Diffie-Hellman debiles
    # ssl-enum-ciphers : Cifrados debiles (RC4, DES, 3DES, EXPORT)
    # ------------------------------------------------------------------
    Write-Info "Analizando vulnerabilidades SSL/TLS..."
    if (Test-PuertoAbierto $Hosts "443") {
        Invoke-Nmap ($Hosts + @("-p", "443,8443,465,993,995", "--open", "--script",
            "ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,ssl-enum-ciphers")) `
            -Etiqueta "SSL/TLS - Heartbleed, POODLE, Logjam, cifrados debiles"
    } else { Write-Log "[SSL Vuln] Sin HTTPS detectado." }

    # ------------------------------------------------------------------
    # 5.5 RDP - VULNERABILIDADES
    # rdp-vuln-ms12-020   : DoS en RDP (CVE-2012-0152)
    # rdp-enum-encryption : Cifrado debil o sin NLA habilitado
    # ------------------------------------------------------------------
    Write-Info "Analizando vulnerabilidades RDP..."
    if (Test-PuertoAbierto $Hosts "3389") {
        Invoke-Nmap ($Hosts + @("-p", "3389", "--open", "--script",
            "rdp-vuln-ms12-020,rdp-enum-encryption")) `
            -Etiqueta "RDP - MS12-020, cifrado debil, sin NLA"
    } else { Write-Log "[RDP Vuln] Sin RDP expuesto." }

    # ------------------------------------------------------------------
    # 5.6 FTP - VULNERABILIDADES
    # ftp-vsftpd-backdoor : Backdoor en vsftpd 2.3.4 (CVE-2011-2523)
    # ftp-proftpd-backdoor: Backdoor en ProFTPD (CVE-2010-4221)
    # ftp-libopie         : Vulnerabilidad en libopie FTP
    # ------------------------------------------------------------------
    Write-Info "Analizando vulnerabilidades FTP..."
    if (Test-PuertoAbierto $Hosts "21") {
        Invoke-Nmap ($Hosts + @("-p", "21", "--open", "--script",
            "ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie")) `
            -Etiqueta "FTP - Backdoors vsftpd/ProFTPD"
    } else { Write-Log "[FTP Vuln] Sin FTP expuesto." }

    # ------------------------------------------------------------------
    # 5.7 DNS - VULNERABILIDADES
    # dns-zone-transfer: Transferencia de zona sin restriccion (filtra toda la zona)
    # dns-recursion    : DNS abierto con recursion (vector de amplificacion DDoS)
    # dns-cache-snoop  : Cache snooping (revela dominios consultados)
    # ------------------------------------------------------------------
    Write-Info "Analizando vulnerabilidades DNS..."
    Invoke-Nmap @("-Pn", "-sU", "-p", "53", "--open", "--script",
        "dns-zone-transfer,dns-recursion,dns-cache-snoop", $GatewayIP) `
        -Etiqueta "DNS - Transferencia de zona, recursion abierta"

    # ------------------------------------------------------------------
    # 5.8 BASES DE DATOS - VULNERABILIDADES
    # mysql-vuln-cve2012-2122: MySQL auth bypass por race condition
    # ms-sql-config          : Configuracion insegura en SQL Server
    # ms-sql-empty-password  : SQL Server con cuenta sa sin contrasena
    # mysql-empty-password   : MySQL con root sin contrasena
    # ------------------------------------------------------------------
    Write-Info "Analizando vulnerabilidades en bases de datos..."
    Invoke-Nmap ($Hosts + @("-p", "3306,1433,5432", "--open", "--script",
        "mysql-vuln-cve2012-2122,ms-sql-config,ms-sql-empty-password,mysql-empty-password")) `
        -Etiqueta "BBDD - Auth bypass MySQL, SQL Server inseguro"

    # ------------------------------------------------------------------
    # 5.9 SERVICIOS VARIOS
    # distcc-cve2004-2687: distcc RCE sin autenticacion (CVE-2004-2687)
    # realvnc-auth-bypass: RealVNC sin autenticacion (CVE-2006-2369)
    # x11-access         : Servidor X11 sin autenticacion (permite control remoto)
    # ipmi-cipher-zero   : IPMI Cipher 0 - acceso BMC sin autenticacion
    # ------------------------------------------------------------------
    Write-Info "Analizando otros servicios vulnerables..."
    Invoke-Nmap ($Hosts + @("--open", "--script",
        "distcc-cve2004-2687,realvnc-auth-bypass,x11-access,ipmi-cipher-zero")) `
        -Etiqueta "Otros - distcc RCE, VNC sin auth, X11, IPMI"

    # ------------------------------------------------------------------
    # 5.10 LDAP / ACTIVE DIRECTORY
    # Util en entornos corporativos con controladores de dominio Windows
    # ldap-search  : Enumeracion de usuarios, grupos y politicas
    # ldap-rootdse : Informacion del directorio raiz (version, dominio, etc.)
    # ------------------------------------------------------------------
    Write-Info "Comprobando LDAP / Active Directory..."
    if (Test-PuertoAbierto $Hosts "389") {
        Invoke-Nmap ($Hosts + @("-p", "389,636,3268,3269", "--open", "--script",
            "ldap-search,ldap-rootdse")) `
            -Etiqueta "LDAP / Active Directory - Enumeracion"
    } else { Write-Log "[LDAP] Sin LDAP expuesto." }

    Write-Ok "Fase 5 completada."
}

function Invoke-AnalisisGateway {
    param([string]$GatewayIP)
    Write-Seccion "ANALISIS DEL GATEWAY $GatewayIP"

    Invoke-Nmap @("-Pn", "-sV", "-O", "--osscan-guess", "--top-ports", "200", $GatewayIP) `
        -Etiqueta "Puertos, servicios y OS"
    Invoke-Nmap @("-Pn", "-p", "80,443,8080,8443",
        "--script", "http-title,http-auth-finder", $GatewayIP) -Etiqueta "Panel web"
    Invoke-Nmap @("-Pn", "-sU", "-p", "1900",
        "--script", "upnp-info", $GatewayIP) -Etiqueta "UPnP"
}

function Write-Resumen {
    param([string[]]$Hosts, [string]$Red, [string]$GatewayIP, [string]$MiIP)
    $linea = "#" * 53
    Write-Log ""; Write-Log $linea
    Write-Log "             RESUMEN EJECUTIVO                      "
    Write-Log $linea
    Write-Log "FECHA AUDITORIA: $(Get-Date)"
    Write-Log "RED ANALIZADA: $Red"
    Write-Log "GATEWAY: $GatewayIP"
    Write-Log "AUDITOR (IP): $MiIP"
    Write-Log "HOSTS VIVOS DETECTADOS: $($Hosts.Count)"
    Write-Log ""
    Write-Log "Metodologia: FASE 1 ARP > FASE 2 Puertos+OS > FASE 3 Enumeracion > FASE 4 Credenciales > FASE 5 Vulnerabilidades"
    Write-Log $linea
    Write-Log "        FIN DEL INFORME - AUDITORIA COMPLETADA     "
    Write-Log $linea
}

# =====================================================
# INICIO
# =====================================================
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Warn "nmap no encontrado. Descargalo desde https://nmap.org/download.html"
    exit 1
}

$red = Get-RedLocal
$script:MI_IP   = $red.MiIP
$MI_RED         = $red.Red
$MI_GATEWAY     = $red.Gateway

# Usar $PSScriptRoot para guardar el informe en la misma carpeta del .ps1
# Funciona correctamente desde pendrive, red o cualquier ruta
$script:LOGFILE = Join-Path $PSScriptRoot "Informe_Auditoria_$(Get-Date -Format 'dd-MM-yyyy_HHmm').txt"

Write-Ok "Red detectada : $MI_RED"
Write-Ok "Gateway       : $MI_GATEWAY"
Write-Ok "Mi IP         : $script:MI_IP"
Write-Ok "Informe       : $script:LOGFILE"

$linea = "#" * 53
@"
$linea
       AUDITORIA DE SEGURIDAD DE RED LOCAL
       Metodologia: Pentester Senior - PowerShell
$linea
FECHA: $(Get-Date)
RED ANALIZADA:      $MI_RED
GATEWAY:            $MI_GATEWAY
DISPOSITIVO ORIGEN: $script:MI_IP
$linea
"@ | Set-Content -Path $script:LOGFILE -Encoding UTF8

Get-InfoAuditor
$hostsVivos = Invoke-Fase1 -Red $MI_RED
Invoke-Fase2 -Hosts $hostsVivos
Invoke-Fase3 -Hosts $hostsVivos -GatewayIP $MI_GATEWAY
Invoke-Fase4 -Hosts $hostsVivos
Invoke-Fase5 -Hosts $hostsVivos -GatewayIP $MI_GATEWAY
Invoke-AnalisisGateway -GatewayIP $MI_GATEWAY
Write-Resumen -Hosts $hostsVivos -Red $MI_RED -GatewayIP $MI_GATEWAY -MiIP $script:MI_IP

Write-Ok ""
Write-Ok "====================================================="
Write-Ok "  Auditoria completada. Informe: $script:LOGFILE"
Write-Ok "====================================================="
