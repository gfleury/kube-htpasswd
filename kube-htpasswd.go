package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/foomo/htpasswd"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

var (
	kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	kubeFactory     cmdutil.Factory

	createNewSecret bool
	dryRun          bool
	arguedPassword  bool
	stdinPassword   bool
	md5Hash         bool
	bcryptHash      bool
	cryptHash       bool
	shaHash         bool
	noHash          bool
	deleteUser      bool
	verifyUser      bool
)

var rootCmd = &cobra.Command{
	Use: `kube-htpasswd [-cimBdpsDv] secretName username
  kube-htpasswd -b[cmBdpsDv] secretName username password
  kube-htpasswd -n[imBdps] secretName username
  kube-htpasswd -nb[mBdps] secretName username password`,
	DisableFlagsInUseLine: true,
	Args: func(cmd *cobra.Command, args []string) error {
		n := 2
		if arguedPassword {
			n = 3
		}
		if len(args) != n {
			return fmt.Errorf("accepts %d arg(s), received %d", n, len(args))
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		var secretName = args[0]
		var username = args[1]
		var password string
		if len(args) == 3 {
			password = args[2]
		}

		if arguedPassword && password == "" {
			return fmt.Errorf("password not specified")
		}

		if *kubeConfigFlags.Namespace == "" {
			*kubeConfigFlags.Namespace = v1.NamespaceDefault
		}

		// creates the clientset
		clientset, err := kubeFactory.KubernetesClientSet()
		if err != nil {
			return err
		}

		var secret *v1.Secret

		if createNewSecret {
			newSecret := &v1.Secret{
				Data: map[string][]byte{
					"auth": {},
				},
				Type: v1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{
					Name: secretName,
				},
			}
			if !dryRun {
				secret, err = clientset.CoreV1().Secrets(*kubeConfigFlags.Namespace).Create(context.TODO(), newSecret, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("failed to create secret %s on namespace %s: %s", secretName, *kubeConfigFlags.Namespace, err.Error())
				}
			} else {
				secret = newSecret
			}

		} else {
			secret, err = clientset.CoreV1().Secrets(*kubeConfigFlags.Namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get secret %s on namespace %s: %s", secretName, *kubeConfigFlags.Namespace, err.Error())
			}
		}

		var passwords htpasswd.HashedPasswords
		if htpasswdBuffered, ok := secret.Data["auth"]; ok {
			passwords, err = htpasswd.ParseHtpasswd(htpasswdBuffered)
			if err != nil {
				return fmt.Errorf("failed to parse htpassword file from secret: %s", err.Error())
			}
		} else {
			return fmt.Errorf("failed to get auth field from secret %s on namespace %s (check data.auth in the Secret)", secretName, *kubeConfigFlags.Namespace)
		}

		if deleteUser {
			delete(passwords, username)
		} else {
			var hashType htpasswd.HashAlgorithm = htpasswd.HashAPR1

			if shaHash {
				hashType = htpasswd.HashSHA
			} else if bcryptHash {
				hashType = htpasswd.HashBCrypt
			} else if md5Hash {
				hashType = htpasswd.HashAPR1
			} else if cryptHash {
				return fmt.Errorf("crypt isn't supported")
			} else if noHash {
				return fmt.Errorf("plaintext isn't supported")
			}

			if !stdinPassword && !arguedPassword && password == "" {
				fmt.Print("Enter password: ")
				bytePassword, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return fmt.Errorf("failed to read password from stdin")
				}
				password = strings.TrimSuffix(string(bytePassword), "\n")
				fmt.Println("")
			}

			if verifyUser {
				check := false
				switch hashType {
				case htpasswd.HashAPR1:
					check = apr1_crypt.New().Verify(passwords[username], []byte(password)) == nil
				case htpasswd.HashSHA:
					s := sha1.New()
					s.Write([]byte(password))
					check = "{SHA}"+base64.StdEncoding.EncodeToString(s.Sum(nil)) == passwords[username]
				case htpasswd.HashBCrypt:
					check = bcrypt.CompareHashAndPassword([]byte(passwords[username]), []byte(password)) == nil
				}
				if check {
					fmt.Printf("Password match!\n")
					return nil
				}
				return fmt.Errorf("password don't match")
			}

			err = passwords.SetPassword(username, password, hashType)
			if err != nil {
				return fmt.Errorf("failed to set password: %s", err.Error())
			}
		}

		secret.Data["auth"] = passwords.Bytes()

		if !dryRun {
			_, err = clientset.CoreV1().Secrets(*kubeConfigFlags.Namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})

			if err != nil {
				return fmt.Errorf("failed to update secret %s on namespace %s: %s", secretName, *kubeConfigFlags.Namespace, err.Error())
			}
			fmt.Printf("Secret %s updated sucessfully on namespace %s\n", secretName, *kubeConfigFlags.Namespace)
		} else {
			fmt.Print(string(passwords.Bytes()))
		}
		return nil
	},
}

func init() {
	kubeConfigFlags.AddFlags(rootCmd.PersistentFlags())

	rootCmd.Flag("context").Shorthand = "C"
	rootCmd.Flag("namespace").Shorthand = "N"
	rootCmd.Flag("server").Shorthand = ""

	err := rootCmd.PersistentFlags().MarkHidden("as")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = rootCmd.PersistentFlags().MarkHidden("as-group")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = rootCmd.PersistentFlags().MarkHidden("cache-dir")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	kubeFactory = cmdutil.NewFactory(matchVersionKubeConfigFlags)

	if *kubeConfigFlags.Context == "" && os.Getenv("KUBECONTEXT") != "" {
		*kubeConfigFlags.Context = os.Getenv("KUBECONTEXT")
	}

	rootCmd.Flags().BoolVarP(&createNewSecret, "create-secret", "c", false, "Create a new secret.")
	rootCmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Don't update secret; display results on stdout.")
	rootCmd.Flags().BoolVarP(&arguedPassword, "argued-password", "b", false, "Use the password from the command line rather than prompting for it.")
	rootCmd.Flags().BoolVarP(&stdinPassword, "stdin-password", "i", false, "Read password from stdin without verification (for script usage).")
	rootCmd.Flags().BoolVarP(&md5Hash, "md5", "m", false, "Force MD5 encryption of the password.")
	rootCmd.Flags().BoolVarP(&bcryptHash, "bcrypt", "B", false, "Force bcrypt encryption of the password (very secure).")
	rootCmd.Flags().BoolVarP(&cryptHash, "crypt", "d", false, "Force CRYPT encryption of the password (8 chars max, insecure).")
	rootCmd.Flags().BoolVarP(&shaHash, "sha", "s", false, "Force SHA encryption of the password (insecure).")
	rootCmd.Flags().BoolVarP(&noHash, "plaintext", "p", false, "Do not encrypt the password (plaintext, insecure).")
	rootCmd.Flags().BoolVarP(&deleteUser, "delete", "D", false, "Delete the specified user.")
	rootCmd.Flags().BoolVarP(&verifyUser, "verify", "v", false, "Verify password for the specified user.")

	err = rootCmd.Flags().MarkDeprecated("crypt", "isn't supported")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = rootCmd.Flags().MarkDeprecated("plaintext", "isn't supported")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
