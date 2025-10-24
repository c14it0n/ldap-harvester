#!/usr/bin/env python3
import argparse
import sys
import ssl
import re
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, core

DEFAULT_FILTER = '(|(objectClass=person)(objectClass=user)(objectClass=organizationalPerson))'

def parse_args():
    p = argparse.ArgumentParser(description="Enumerar usuarios LDAP (HTB/CTF). Ejecútalo solo en entornos autorizados.")
    p.add_argument('-t', '--target', required=True, help='IP o hostname del servidor LDAP')
    p.add_argument('-p', '--port', type=int, default=389, help='Puerto LDAP (default 389)')
    p.add_argument('-b', '--base', required=True, help='Base DN (ej. "dc=example,dc=com")')
    p.add_argument('-u', '--user', help='Bind DN (opcional)')
    p.add_argument('-w', '--password', help='Bind password (opcional)')
    p.add_argument('--starttls', action='store_true', help='Negociar StartTLS antes de bind (recomendado)')
    p.add_argument('--insecure', action='store_true', help='No validar certificados TLS (solo para labs)')
    p.add_argument('--outfile', default='users.txt', help='Archivo de salida para usuarios')
    p.add_argument('--skipped', default='skipped_dn.log', help='Archivo para DNs no mapeables')
    p.add_argument('--secrets-out', default='found_secrets.txt', help='Archivo para "secrets" si --find-passwords')
    p.add_argument('--find-passwords', action='store_true', help='Buscar patrones tipo "password" en description (solo labs)')
    p.add_argument('--filter', default=DEFAULT_FILTER, help='Filtro LDAP (por defecto amplio)')
    p.add_argument('--page-size', type=int, default=1000, help='Tamaño de página para búsquedas paginadas')
    return p.parse_args()

def dn_to_fname_lname(dn):
    """Extrae el CN del DN y lo transforma a fname.lname (lowercase)."""
    m = re.search(r'CN=([^,]+)', dn, flags=re.IGNORECASE)
    if not m:
        return None
    cn = m.group(1).strip()
    # Reemplazar múltiples espacios por uno, luego unir con puntos
    parts = [p for p in re.split(r'\s+', cn) if p]
    if len(parts) >= 1:
        return '.'.join(p.lower() for p in parts)
    return None

def find_password_like_strings(value):
    if not value:
        return []
    patterns = [
        r'(?i)\bpass(?:word)?\b[:\s]*([^\s,;"]{4,128})',
        r'(?i)\bpwd\b[:\s]*([^\s,;"]{2,128})',
        r'(?i)\bpass[:\s]*([^\s,;"]{2,128})',
        r'(?i)\bcontrase(?:ñ|n)a\b[:\s]*([^\s,;"]{2,128})'
    ]
    found = []
    for pat in patterns:
        for m in re.findall(pat, value):
            found.append(m)
    if not found and re.search(r'(?i)\b(pass(word)?|pwd|contrase(n|ñ)a)\b', value):
        found.append(value.strip())
    return found

def safe_get_attr(entry_attrs, key):
    """Normaliza lectura de atributos que pueden ser str o list."""
    val = entry_attrs.get(key)
    if isinstance(val, list):
        return val[0] if val else None
    return val

def add_group_members(conn, base_dn, users, seen_dns, skipped_file, find_passwords, found_secrets):
    """Recorre groups, procesa sus members e intenta mapear usernames."""
    try:
        conn.search(search_base=base_dn, search_filter='(objectClass=group)', search_scope=SUBTREE, attributes=['member'])
    except Exception as e:
        print("[!] Error buscando groups:", e)
        return

    for g in conn.entries:
        members = []
        try:
            members = g.member.values if hasattr(g, 'member') and g.member else []
        except Exception:
            m = getattr(g, 'member', None)
            if m:
                members = m if isinstance(m, list) else [m]

        for dn in members:
            if not dn or dn in seen_dns:
                continue
            seen_dns.add(dn)

            # Intentar derivar username desde la propia cadena DN (CN)
            username = dn_to_fname_lname(dn)

            # Si no se pudo derivar, intentar una búsqueda BASE por el DN (si ACL lo permite)
            if not username:
                try:
                    conn.search(search_base=dn, search_filter='(objectClass=*)', search_scope='BASE',
                                attributes=['uid', 'sAMAccountName', 'cn', 'description', 'mail'])
                    if conn.entries:
                        ent = conn.entries[0]
                        ent_attrs = ent.entry_attributes_as_dict
                        uid = safe_get_attr(ent_attrs, 'uid')
                        sam = safe_get_attr(ent_attrs, 'sAMAccountName')
                        cn = safe_get_attr(ent_attrs, 'cn')
                        desc = safe_get_attr(ent_attrs, 'description')
                        if uid:
                            username = uid
                        elif sam:
                            username = sam
                        elif cn:
                            # cn puede ser lista
                            cn_val = cn if isinstance(cn, str) else (cn[0] if isinstance(cn, list) and cn else None)
                            username = '.'.join(cn_val.split()).lower() if cn_val else None

                        if find_passwords and desc:
                            # buscar secretos en description
                            for s in find_password_like_strings(desc if isinstance(desc, str) else str(desc)):
                                found_secrets.append({'dn': dn, 'match': s, 'context': desc})
                except Exception:
                    # suele ocurrir por ACLs; seguiremos intentando con CN derivado
                    username = username  # keeps None if still none

            if username:
                users.append(f"{username}  # DN={dn}")
            else:
                # Registrar DN no mapeable
                try:
                    with open(skipped_file, 'a', encoding='utf-8') as sf:
                        sf.write(dn + "\n")
                except Exception:
                    pass

def main():
    args = parse_args()

    print("[*] ADVERTENCIA: Ejecuta esto únicamente en entornos autorizados (HTB/CTF/lab).")
    print(f"[*] Conectando a: {args.target}:{args.port} | Base DN: {args.base}")
    print(f"[*] Filtro LDAP: {args.filter}")

    tls = None
    if args.insecure:
        tls = Tls(validate=ssl.CERT_NONE)
    else:
        tls = Tls(validate=ssl.CERT_REQUIRED)

    server = Server(args.target, port=args.port, get_info=ALL, tls=tls)

    try:
        if args.user and args.password:
            conn = Connection(server, user=args.user, password=args.password, auto_bind=False, auto_referrals=False)
        else:
            conn = Connection(server, auto_bind=False, auto_referrals=False)

        conn.open()
        if args.starttls:
            try:
                print("[*] Iniciando StartTLS...")
                conn.start_tls()
            except core.exceptions.LDAPStartTLSError as e:
                print("[!] StartTLS falló:", e)
                conn.unbind()
                sys.exit(1)

        if not conn.bind():
            print("[!] Bind fallido:", conn.result)
            conn.unbind()
            sys.exit(1)
        else:
            print("[+] Bind OK:", conn.result['description'])

        attrs = ['cn', 'uid', 'sAMAccountName', 'description', 'mail']
        users = []
        seen_dns = set()
        found_secrets = []

        # paged_search generator: más robusto
        try:
            entries = conn.extend.standard.paged_search(
                search_base=args.base,
                search_filter=args.filter,
                search_scope=SUBTREE,
                attributes=attrs,
                paged_size=args.page_size,
                generator=True
            )
        except Exception as e:
            print("[!] paged_search error, intentando search normal:", e)
            # fallback: simple search
            conn.search(search_base=args.base, search_filter=args.filter, search_scope=SUBTREE, attributes=attrs)
            entries = conn.response

        total_seen = 0
        for entry in entries:
            # entries puede ser dict (generator) o ldap3 entry objects in fallback
            if isinstance(entry, dict):
                if entry.get('type') != 'searchResEntry':
                    continue
                dn = entry.get('dn')
                attrs_dict = entry.get('attributes', {})
                total_seen += 1
            else:
                # ldap3 Entry object
                dn = entry.entry_dn
                attrs_dict = entry.entry_attributes_as_dict
                total_seen += 1

            if not dn:
                continue
            seen_dns.add(dn)

            # obtener atributos con seguridad
            uid = safe_get_attr(attrs_dict, 'uid')
            sam = safe_get_attr(attrs_dict, 'sAMAccountName')
            cn_attr = safe_get_attr(attrs_dict, 'cn')
            desc = safe_get_attr(attrs_dict, 'description')

            username = None
            if uid:
                username = uid
            elif sam:
                username = sam
            elif cn_attr:
                # cn puede ser lista o string
                cn_val = cn_attr if isinstance(cn_attr, str) else (cn_attr[0] if isinstance(cn_attr, list) and cn_attr else None)
                if cn_val:
                    username = '.'.join(cn_val.split()).lower()

            if username:
                users.append(f"{username}  # DN={dn}")
            else:
                # intentar derivar desde DN CN si no existe cn attr legible
                dn_derived = dn_to_fname_lname(dn)
                if dn_derived:
                    users.append(f"{dn_derived}  # DN={dn}")
                else:
                    # guardar DN no mapeable
                    try:
                        with open(args.skipped, 'a', encoding='utf-8') as sf:
                            sf.write(dn + "\n")
                    except Exception:
                        pass

            # buscar secrets en description si se pide (solo labs)
            if args.find_passwords and desc:
                for s in find_password_like_strings(desc if isinstance(desc, str) else str(desc)):
                    found_secrets.append({'dn': dn, 'match': s, 'context': desc})

        # Ahora añadir miembros de grupos (por si hay miembros cuyos atributos están protegidos)
        add_group_members(conn, args.base, users, seen_dns, args.skipped, args.find_passwords, found_secrets)

        # Escribir usuarios (ordenar y deduplicar)
        unique_users = []
        seen_usernames = set()
        for line in users:
            uname = line.split()[0] if line else line
            if uname and uname not in seen_usernames:
                unique_users.append(line)
                seen_usernames.add(uname)

        if unique_users:
            with open(args.outfile, 'w', encoding='utf-8') as fh:
                for u in unique_users:
                    fh.write(u + "\n")
            print(f"[+] Escrita lista de {len(unique_users)} usuarios en: {args.outfile}")
        else:
            print("[*] No se encontraron usuarios con el filtro dado.")

        # Escribir found_secrets si corresponde
        if args.find_passwords:
            if found_secrets:
                with open(args.secrets_out, 'w', encoding='utf-8') as fh:
                    for s in found_secrets:
                        fh.write(f"DN: {s['dn']}\nMATCH: {s['match']}\nCONTEXT: {s['context']}\n---\n")
                print(f"[!] {len(found_secrets)} coincidencias escritas en {args.secrets_out}")
            else:
                print("[*] No se encontraron cadenas tipo 'password' en 'description' según el heurístico.")

        conn.unbind()

    except Exception as e:
        print("[!] Error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
