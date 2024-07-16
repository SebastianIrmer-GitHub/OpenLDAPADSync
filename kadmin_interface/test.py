import kadmin

keytab_path = 'admin.keytab'
realm = 'KRB'
admin = kadmin.Kadmin(keytab_path, realm)
info =admin.get_principal_info(f'testuser123@{realm}')
print(info)
# principals = admin.list_principals()
# print(principals)


# admin.add_principal('newuser@KRB', 'password', 0, 0, 0)
# admin.change_password('newuser@KRB', 'newpassword')
# admin.modify_principal('newuser@KRB', 0, 1)
# admin.delete_principal('newuser@KRB')
