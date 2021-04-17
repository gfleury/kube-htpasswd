module github.com/gfleury/kube-htpasswd

go 1.13

require (
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/foomo/htpasswd v0.0.0-20200116085101-e3a90e78da9c
	github.com/spf13/cobra v1.1.3
	golang.org/x/crypto v0.0.0-20210415154028-4f45737414dc
	golang.org/x/term v0.0.0-20210406210042-72f3dc4e9b72
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.20.6
	k8s.io/cli-runtime v0.20.6
	k8s.io/kubectl v0.20.6
)
