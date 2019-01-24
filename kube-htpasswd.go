package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/foomo/htpasswd"

	"golang.org/x/crypto/ssh/terminal"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const usage string = `
kube-htpasswd [-cimBdpsDv] [-C cost] secretName username
kube-htpasswd -b[cmBdpsDv] [-C cost] secretName username password

kube-htpasswd -n[imBdps] [-C cost] secretName username
kube-htpasswd -nb[mBdps] [-C cost] secretName username password
`

// Usage is default used by flag to print the default tool usage
var Usage = func() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	fmt.Print(usage)
	flag.PrintDefaults()
}

func main() {
	var createNewSecret = flag.Bool("c", false, "Create a new secret.")
	var dryRun = flag.Bool("n", false, "Don't update secret; display results on stdout.")
	var arguedPassword = flag.Bool("b", false, "Use the password from the command line rather than prompting for it.")
	var stdinPassword = flag.Bool("i", false, "Read password from stdin without verification (for script usage).")
	var md5Hash = flag.Bool("m", false, "Force MD5 encryption of the password.")
	var bcryptHash = flag.Bool("B", false, "Force bcrypt encryption of the password (very secure).")
	// var bcryptComputingTime = flag.Int("C", 5, "Set the computing time used for the bcrypt algorithm (higher is more secure but slower, default: 5, valid: 4 to 31).")
	var cryptHash = flag.Bool("d", false, "Force CRYPT encryption of the password (8 chars max, insecure).")
	var shaHash = flag.Bool("s", true, "Force SHA encryption of the password (insecure).")
	var noHash = flag.Bool("p", false, "Do not encrypt the password (plaintext, insecure).")
	var deleteUser = flag.Bool("D", false, "Delete the specified user.")
	var verifyUser = flag.Bool("v", false, "Verify password for the specified user.")
	var context = flag.String("C", "", "Specify Kubernetes config context to use (same from kubectl config).")
	var kubeNamespace = flag.String("N", "default", "Specify Kubernetes namespace.")

	flag.Parse()

	var secretName = flag.Arg(0)
	var username = flag.Arg(1)
	var password = flag.Arg(2)

	if (secretName == "" || username == "") || (*arguedPassword && password == "") {
		Usage()
		os.Exit(2)
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.DefaultClientConfig = &clientcmd.DefaultClientConfig

	overrides := &clientcmd.ConfigOverrides{ClusterDefaults: clientcmd.ClusterDefaults}

	if *context != "" {
		overrides.CurrentContext = *context
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()

	if err != nil {
		// creates the in-cluster config
		config, err = rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	var secret *v1.Secret

	if *createNewSecret {
		newSecret := &v1.Secret{
			Data: map[string][]byte{
				"auth": []byte{},
			},
			Type: v1.SecretTypeOpaque,
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
			},
		}
		secret, err = clientset.CoreV1().Secrets(*kubeNamespace).Create(newSecret)
		if err != nil {
			fmt.Printf("Failed to create secret %s on namespace %s: %s\n", secretName, *kubeNamespace, err.Error())
			return
		}
	} else {
		secret, err = clientset.CoreV1().Secrets(*kubeNamespace).Get(secretName, metav1.GetOptions{})
		if err != nil {
			fmt.Printf("Failed to get secret %s on namespace %s: %s\n", secretName, *kubeNamespace, err.Error())
			return
		}
	}

	var htpasswdBuffered []byte
	var ok bool

	if htpasswdBuffered, ok = secret.Data["auth"]; !ok {
		fmt.Printf("Failed to get auth field from secret %s on namespace %s (check data.auth in the Secret).\n", secretName, *kubeNamespace)
		return
	}

	passwords, err := htpasswd.ParseHtpasswd(htpasswdBuffered)
	if err != nil {
		fmt.Printf("Failed to parse htpassword file from secret: %s.\n", err.Error())
		return
	}

	if *deleteUser {
		delete(passwords, username)
	} else {
		var hashType htpasswd.HashAlgorithm = htpasswd.HashSHA

		if *shaHash {
			hashType = htpasswd.HashSHA
		} else if *bcryptHash {
			fmt.Println("BCrypt isn't supported.")
			return
		} else if *cryptHash {
			fmt.Println("Crypt isn't supported.")
			return
		} else if *md5Hash {
			fmt.Println("MD5 isn't supported.")
			return
		} else if *noHash {
			fmt.Println("PlainText isn't supported.")
			return
		}

		if !*stdinPassword && !*arguedPassword && password == "" {
			fmt.Print("Enter password: ")
			bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				fmt.Printf("Failed to read password from stdin.\n")
				return
			}
			password = strings.TrimSuffix(string(bytePassword), "\n")
			fmt.Println("")
		}

		if *verifyUser {
			err = passwords.SetPassword("verify", password, hashType)
			if err != nil {
				fmt.Printf("Failed to set password: %s.\n", err.Error())
				return
			}
			if passwords[username] == passwords["verify"] {
				fmt.Printf("Password match!\n")
			} else {
				fmt.Printf("Password don't match!\n")
			}
			return
		} else {
			err = passwords.SetPassword(username, password, hashType)
			if err != nil {
				fmt.Printf("Failed to set password: %s.\n", err.Error())
				return
			}
		}
	}

	secret.Data["auth"] = passwords.Bytes()

	if !*dryRun {
		_, err = clientset.CoreV1().Secrets(*kubeNamespace).Update(secret)

		if err != nil {
			fmt.Printf("Failed to update secret %s on namespace %s: %s.\n", secretName, *kubeNamespace, err.Error())
			return
		}

		fmt.Printf("Secret %s updated sucessfully on namespace %s.\n", secretName, *kubeNamespace)
		return
	} else {
		fmt.Print(string(passwords.Bytes()))
	}
}
