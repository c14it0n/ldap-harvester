# ldap-harvester

**ldap-harvester** es una herramienta para la **enumeración de usuarios y objetos en servidores LDAP/Active Directory** durante actividades de **Pentesting** y **auditorías de seguridad** autorizadas.

El objetivo principal es obtener una vista completa y consolidada de los usuarios existentes, incluso cuando algunos de ellos no son visibles mediante búsquedas LDAP tradicionales debido a restricciones de visibilidad (ACLs) o porque solo aparecen referenciados como miembros de grupos.

---

## Características

- **Enumeración completa de usuarios** mediante búsquedas LDAP paginadas.
- **Detección de usuarios referenciados por grupos**, evitando pérdida de cuentas durante la enumeración.
- **Construcción automática de nombres de usuario** a partir de atributos (`uid`, `sAMAccountName`, `cn`) o desde el DN (`CN=Nombre Apellido → nombre.apellido`).
- **Compatibilidad con LDAP y Active Directory**.
- **Salida limpia y deduplicada** en `users.txt`.
- **Registro de objetos no mapeables** en `skipped_dn.log`.
- **Soporte opcional para StartTLS** y entornos con certificados autofirmados.
- Opción adicional para **analizar campos `description`** en búsqueda de menciones a contraseñas cuando se realiza un análisis interno autorizado.

---

## Requisitos

- Python 3.8+
- Biblioteca `ldap3`

Instalación de dependencias:

```bash
pip install ldap3
