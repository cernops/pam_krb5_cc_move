# pam_krb5_cc_move

Pam session module to move a Kerberos credential cache from one location to another.

Default locations for source and destination are as below

```
session  optional pam_krb5_cc_move.so  source=FILE:/tmp/source destination=FILE:/tmp/destination debug
```

if the source cc is missing this is NOT considered an error.

## Use case with SSHD and Kerberos

With SSHD and Kerberos authentication it is not possible to create a keytab at `/run/user/<uid>` since this directory
does not exist when SSHD does the delegation. The workaround is have SSHD delegate to KEYRING and then this pam module
can move the credential to the correct location.

* Configure `/etc/krb5.conf` with cache of `FILE:/run/user/%{uid}/krb5cc`.
* Run sshd with an environment of `KRB5_CONFIG=/etc/krb5_sshd.conf` to use a custom cache location for SSHD only.

```ini
# File /etc/krb5_sshd.conf
[libdefaults]
    default_ccache_name = KEYRING:persistent:%{uid}

include /etc/krb5.conf
```

* Use two pam modules to create $XDG_RUNTIME_DIR and then move the credential there with each login.

```
session optional pam_xdg_runtime_dir.so
session optional pam_krb5_cc_move.so
```

Default source and  destination in pam_krb5_cc_move is `KEYRING:persistant:%{uid}` and  `FILE:/run/user/%{uid}/krb5cc` 

## Links
* pam_xdg_runtime_dir https://github.com/cernops/pam_xdg_runtime_dir
* pam_krb5_cc_move_dir https://github.com/cernops/pam_krb5_cc_move

