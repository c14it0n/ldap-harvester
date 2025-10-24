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

## Instalación de dependencias:

```bash
pip install ldap3
```

## Uso
Ejecución básica
```bash
python3 ldap-harvester.py -t <server-ip> -b "dc=example,dc=local"
```
Con StartTLS (si el servidor lo soporta)
```bash
python3 ldap-harvester.py -t <server-ip> -b "dc=example,dc=local" --starttls
```
Entornos con certificados autofirmados
```bash
python3 ldap-harvester.py -t <server-ip> -b "dc=example,dc=local" --starttls --insecure
```
Uso con credenciales (bind autenticado)
```bash
python3 ldap-harvester.py -t <server-ip> -b "dc=example,dc=local" \
  -u "CN=usuario,OU=IT,DC=example,DC=local" -w "Password123"
```
Ajustar el filtro LDAP
```bash
python3 ldap-harvester.py -t <server-ip> -b "dc=example,dc=local" \
  --filter '(|(objectClass=person)(objectClass=user)(objectClass=organizationalPerson)(objectClass=inetOrgPerson))'
```
Cambiar archivos de salida
```bash
python3 ldap-harvester.py -t <server-ip> -b "dc=example,dc=local" \
  --outfile users.txt --skipped skipped_dn.log
```
Generar lista limpia solo con nombres
```bash
cut -d' ' -f1 users.txt | sort -u > users_only.txt
```

## Casos de uso
- ** Reconocimiento de cuentas durante auditorías de seguridad.
- ** Identificación de usuarios referenciados únicamente por pertenencia a grupos.
- ** Preparación de inventarios internos de cuentas en entornos de prueba.
- ** Validación de visibilidad/ACLs sobre atributos de directorio.

## Limitaciones
- ** ACLs: si los atributos están protegidos, solo podrá derivarse el nombre desde el DN.
- ** Nombres complejos: la heurística CN → nombre.apellido puede no ser perfecta en todos los casos (comillas, caracteres especiales, apellidos compuestos).
- ** Referrals/particiones: el script desactiva auto_referrals por defecto para evitar resultados fuera de alcance; habilítalo manualmente si es necesario y controlado.

