[![Build Status](https://travis-ci.org/gfleury/kube-htpasswd.svg?branch=master)](https://travis-ci.org/gfleury/kube-htpasswd) [![codecov](https://codecov.io/gh/gfleury/kube-htpasswd/branch/master/graph/badge.svg)](https://codecov.io/gh/gfleury/kube-htpasswd)

# kube-htpasswd

kube-htpasswd is a tool to edit Kubernetes secrets that contains htpasswd files. Kubernetes secrets with htpasswd files are a common way of implementing basic-auth on nginx-ingress (https://github.com/kubernetes/contrib/tree/master/ingress/controllers/nginx/examples/auth).

## Help

```
Usage:
  kube-htpasswd [-cimBdpsDv] secretName username
  kube-htpasswd -b[cmBdpsDv] secretName username password
  kube-htpasswd -n[imBdps] secretName username
  kube-htpasswd -nb[mBdps] secretName username password

Flags:
  -b, --argued-password                Use the password from the command line rather than prompting for it.
  -B, --bcrypt                         Force bcrypt encryption of the password (very secure).
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
  -C, --context string                 The name of the kubeconfig context to use
  -c, --create-secret                  Create a new secret.
  -D, --delete                         Delete the specified user.
  -n, --dry-run                        Don't update secret; display results on stdout.
  -h, --help                           help for kube-htpasswd
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
  -m, --md5                            Force MD5 encryption of the password.
  -N, --namespace string               If present, the namespace scope for this CLI request
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
      --server string                  The address and port of the Kubernetes API server
  -s, --sha                            Force SHA encryption of the password (insecure).
  -i, --stdin-password                 Read password from stdin without verification (for script usage).
      --tls-server-name string         Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used
      --token string                   Bearer token for authentication to the API server
      --user string                    The name of the kubeconfig user to use
  -v, --verify                         Verify password for the specified user.
```

## How to use

Create a new secret called basic-auth and create a new user called gfleury.

```bash
$ kube-htpasswd -c basic-auth gfleury
```

Create a new user called second_user on a existing secret called basic-auth.
```bash
$ kube-htpasswd basic-auth second_user
```

Create a new user on a existing secret and pass the password as paramater.
```bash
$ kube-htpasswd basic-auth third_user third_password
```

Verify the user third_user password on basic-auth secret.
```bash
$ kube-htpasswd -v basic-auth third_user
```

Delete the user third_user from basic-auth secret.
```bash
$ kube-htpasswd -D basic-auth third_user
```

It by default point to the actual context on ~/.kube and default namespace. To change it use -C and -N.