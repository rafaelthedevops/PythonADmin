#!/usr/bin/env python 

import ldap
import ldif
import sys
import base64

CONSULTA = sys.argv[1]
password = base64.b64decode("your_already_encoded_password")

def authenticate(address, username, password):
    conn = ldap.initialize('ldap://' + address)
    conn.protocol_version = 3
    conn.set_option(ldap.OPT_REFERRALS,0)
    try:
        conn.simple_bind_s(username, password)
    except ldap.INVALID_CREDENTIALS:
        return "Usuario ou senha incorreta"
    except ldap.SERVER_DOWN:
        return "O Servidor parece ter caido"
    except ldap.LDAPError, e:
        if type(e.message) == dict and e.message.has_key('desc'):
            return e.message['desc']
        else:
            return e
    finally:
        ldif_writer = ldif.LDIFWriter(sys.stdout)
        basedn = "OU=Some_OU,DC=my_domain,DC=local"
        results = conn.search_s(basedn,ldap.SCOPE_SUBTREE, "(cn=*%s*)" % CONSULTA)
        for dn, entry in results:
            ldif_writer.unparse(dn,entry)

# calls the authenticate method
authenticate('dc_hostname', 'user@domain.local', password)