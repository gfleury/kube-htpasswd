[![Build Status](https://travis-ci.org/gfleury/kube-htpasswd.svg?branch=master)](https://travis-ci.org/gfleury/kube-htpasswd) [![codecov](https://codecov.io/gh/gfleury/kube-htpasswd/branch/master/graph/badge.svg)](https://codecov.io/gh/gfleury/kube-htpasswd)

# kube-htpasswd

kube-htpasswd is a tool to edit Kubernetes secrets that contains htpasswd files. Kubernetes secrets with htpasswd files are a common way of implementing basic-auth on nginx-ingress (https://github.com/kubernetes/contrib/tree/master/ingress/controllers/nginx/examples/auth).


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