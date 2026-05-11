# Local Network Security Audit

Herramienta de auditoría de seguridad de red local desarrollada en PowerShell, basada en metodología de pentesting profesional estructurada en 5 fases.

---

## Descripción

Script de auditoría automatizada que analiza una red local /24, detecta hosts activos, enumera servicios, identifica vulnerabilidades conocidas y genera un informe detallado en texto plano.

Desarrollado como proyecto práctico durante la realización del **Certificado de Profesionalidad en Seguridad Informática (Nivel 3)**.

---

## Requisitos

El equipo desde el que se ejecuta la auditoría debe cumplir lo siguiente:

- Windows 10 o Windows 11
- PowerShell 5.1 o superior (incluido por defecto en Windows 10/11)
- Nmap con Npcap instalado

### Instalación de Nmap y Npcap

Npcap es imprescindible para el escaneo ARP, detección de OS y escaneos UDP. Sin él, el escaneo fallará.

1. Ejecutar `nmap-7.98-setup.exe` incluido en la carpeta
2. Durante la instalación, marcar la opción **"Install Npcap"**
3. Completar la instalación

El equipo auditor debe estar conectado a la misma red que los equipos a escanear (WiFi o cable). Los equipos de la red auditada no necesitan credenciales ni software adicional, únicamente deben estar encendidos.

---

## Uso

### Opción 1 — Lanzador automático (recomendado)

1. Abrir la carpeta `Auditoria\`
2. Clic derecho sobre `ejecutar.bat`
3. Seleccionar **"Ejecutar como administrador"** (o hacer doble clic, el propio .bat solicitará privilegios automáticamente)
4. Aceptar la ventana de UAC
5. Esperar a que finalice el escaneo (puede tardar varios minutos según el número de equipos en la red)
6. El informe se generará automáticamente en la misma carpeta

> Si se ejecuta desde pendrive, no desconectarlo durante el escaneo.

### Opción 2 — PowerShell manual

```powershell
powershell -ExecutionPolicy Bypass -File .\escaner_pro.ps1
```

---

## Metodología — 5 Fases

| Fase | Descripción |
|------|-------------|
| **Fase 1** | Descubrimiento de hosts activos mediante ARP sweep |
| **Fase 2** | Escaneo completo de puertos TCP/UDP y detección de OS y versiones de servicios |
| **Fase 3** | Enumeración dirigida por servicio: SMB, HTTP/S, SSL/TLS, DNS, SNMP, RDP, SSH, FTP, BBDD |
| **Fase 4** | Detección de credenciales por defecto en paneles web, FTP, SSH, SNMP y bases de datos |
| **Fase 5** | Análisis de vulnerabilidades conocidas por CVE: EternalBlue, Heartbleed, POODLE, Shellshock y más |

---

## Vulnerabilidades detectadas

Entre otras, la herramienta analiza:

- **SMB**: MS17-010 (EternalBlue), MS08-067, DoublePulsar backdoor
- **SSL/TLS**: Heartbleed (CVE-2014-0160), POODLE (CVE-2014-3566), Logjam, cifrados débiles
- **HTTP**: Shellshock, CSRF, XSS DOM/Stored, Apache Struts RCE, directorios expuestos, repositorios .git públicos
- **RDP**: MS12-020, cifrado débil, ausencia de NLA
- **FTP**: Backdoors vsftpd/ProFTPD, acceso anónimo
- **DNS**: Transferencia de zona, recursión abierta, cache snooping
- **BBDD**: MySQL/SQL Server sin autenticación, auth bypass
- **LDAP/AD**: Enumeración de usuarios y políticas
- **Otros**: distcc RCE, RealVNC sin auth, X11 expuesto, IPMI Cipher 0

---

## Informe generado

Al finalizar, la herramienta genera automáticamente un fichero de texto:

```
Informe_Auditoria_DD-MM-YYYY_HHMM.txt
```

El informe incluye:
- Información del equipo auditor (adaptadores, ARP, rutas, conexiones activas)
- Hosts descubiertos y resultados por fase
- Resumen ejecutivo con fecha, red analizada, gateway y total de hosts

---

## Aviso legal

Esta herramienta está desarrollada **exclusivamente para auditorías de seguridad autorizadas** sobre redes propias o con permiso explícito del propietario.

El uso no autorizado sobre redes ajenas puede constituir un delito tipificado en el **artículo 197 bis del Código Penal español** y normativa equivalente en otros países.

**El autor no se hace responsable del uso indebido de esta herramienta.**

---

## Autora

Elena Martín Carpio
Desarrollado como proyecto práctico de ciberseguridad.
Toledo, España
Especialización en Seguridad Informática | Administración de Sistemas

---

## Licencia

MIT License — libre para uso educativo y profesional con fines éticos.
