INDICATOR_PARAM_MAP = {'FileHash-SHA1': 'file:hashes.sha1', 'FileHash-SHA256': 'file:hashes.sha256',
                       'FileHash-MD5': 'file:hashes.md5', 'Domain': 'domain-name:value', 'URL': 'url:value',
                       'IP V4 Address': 'ipv4-addr:value', 'IP Address': 'ipv4-addr:value',
                       'IP V4 CIDR Address': 'ipv4-addr:value', 'IP V6 Address': 'ipv6-addr:value',
                       'IP V6 CIDR Address': 'ipv6-addr:value', 'Email Address': 'email-message:sender_ref.value',
                       'Host': 'domain-name:value', 'Registry': 'windows-registry-key:key',
                       'User': 'user-account:account_login', 'File': 'file:name', 'Process': 'process:name'}

ALPHA_PARAM_MAP = {'gen_org_name': 'name', 'gen_org_description': 'description', 'gen_role': 'roles',
                   'gen_class': 'identity_class', 'gen_sector': 'sectors', 'gen_contact_info': 'contact_information'}

BETA_PARAM_MAP = {'rec_org_name': 'name', 'rec_org_description': 'description', 'rec_role': 'roles',
                  'rec_class': 'identity_class', 'rec_sector': 'sectors', 'rec_contact_info': 'contact_information'
                  }
