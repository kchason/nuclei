package customtemplates

import (
	"context"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/github"
	"github.com/jferrl/go-githubauth"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	"golang.org/x/oauth2"
	"io"
	httpclient "net/http"
	"os"
	"path/filepath"
	"strings"
)

var _ Provider = &customTemplateGitHubRepo{}

type customTemplateGitHubRepo struct {
	owner       string
	reponame    string
	gitCloneURL string
	githubToken string
	auth        *http.BasicAuth
}

// Download This function download the custom github template repository
func (customTemplate *customTemplateGitHubRepo) Download(ctx context.Context) {
	clonePath := customTemplate.getLocalRepoClonePath(config.DefaultConfig.CustomGitHubTemplatesDirectory)

	if !fileutil.FolderExists(clonePath) {
		err := customTemplate.cloneRepo(clonePath, customTemplate.githubToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
		} else {
			gologger.Info().Msgf("Repo %s/%s cloned successfully at %s", customTemplate.owner, customTemplate.reponame, clonePath)
		}
		return
	}
}

func (customTemplate *customTemplateGitHubRepo) Update(ctx context.Context) {
	downloadPath := config.DefaultConfig.CustomGitHubTemplatesDirectory
	clonePath := customTemplate.getLocalRepoClonePath(downloadPath)

	// If folder does not exist then clone/download the repo
	if !fileutil.FolderExists(clonePath) {
		customTemplate.Download(ctx)
		return
	}
	err := customTemplate.pullChanges(clonePath, customTemplate.githubToken)
	if err != nil {
		gologger.Error().Msgf("%s", err)
	} else {
		gologger.Info().Msgf("Repo %s/%s successfully pulled the changes.\n", customTemplate.owner, customTemplate.reponame)
	}
}

// NewGitHubProviders returns new instance of GitHub providers for downloading custom templates
func NewGitHubProviders(options *types.Options) ([]*customTemplateGitHubRepo, error) {
	providers := []*customTemplateGitHubRepo{}
	var auth *http.BasicAuth
	// If the user has provided GitHub app key and installation ID, then use it to create the client instead of an
	// incognito client or a client with a token
	var gitHubClient *github.Client
	if options.GitHubAppID > 0 && options.GitHubInstallationID > 0 {
		// Determine if the user provided a private key or a path to a private key
		if options.GitHubAppKey != "" {
			gitHubClient = getGHClientWithAppCert(options.GitHubAppID, options.GitHubInstallationID, []byte(options.GitHubAppKey))
		} else if options.GitHubAppKeyFile != "" {
			gitHubClient = getGHClientWithAppCertPath(options.GitHubAppID, options.GitHubInstallationID, options.GitHubAppKeyFile)
		} else {
			gologger.Fatal().Msgf("GitHub App key or App key file is required for GitHub App authentication")
		}
		// If the client was created, then generate an auth object from the installation ID
		if gitHubClient != nil {
			auth = getApplicationAuth(gitHubClient, options.GitHubInstallationID, context.Background())
		}
	} else {
		gitHubClient = getGHClientIncognito()
	}

	if options.GitHubTemplateDisableDownload {
		return providers, nil
	}

	for _, repoName := range options.GitHubTemplateRepo {
		owner, repo, err := getOwnerAndRepo(repoName)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			continue
		}
		githubRepo, err := getGitHubRepo(gitHubClient, owner, repo, options.GitHubToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			continue
		}
		// If there is a token set, then generate the basic auth object
		if options.GitHubToken != "" {
			auth = getAuth(owner, options.GitHubToken)
		}
		customTemplateRepo := &customTemplateGitHubRepo{
			owner:       owner,
			reponame:    repo,
			gitCloneURL: githubRepo.GetCloneURL(),
			githubToken: options.GitHubToken,
			auth:        auth,
		}

		providers = append(providers, customTemplateRepo)

		customTemplateRepo.restructureRepoDir()
	}
	return providers, nil
}

func (customTemplateRepo *customTemplateGitHubRepo) restructureRepoDir() {
	customGitHubTemplatesDirectory := config.DefaultConfig.CustomGitHubTemplatesDirectory
	oldRepoClonePath := filepath.Join(customGitHubTemplatesDirectory, customTemplateRepo.reponame+"-"+customTemplateRepo.owner)
	newRepoClonePath := customTemplateRepo.getLocalRepoClonePath(customGitHubTemplatesDirectory)

	if fileutil.FolderExists(oldRepoClonePath) && !fileutil.FolderExists(newRepoClonePath) {
		_ = folderutil.SyncDirectory(oldRepoClonePath, newRepoClonePath)
	}
}

// getOwnerAndRepo returns the owner, repo, err from the given string
// e.g., it takes input projectdiscovery/nuclei-templates and
// returns owner => projectdiscovery, repo => nuclei-templates
func getOwnerAndRepo(reponame string) (owner string, repo string, err error) {
	s := strings.Split(reponame, "/")
	if len(s) != 2 {
		err = errors.Errorf("wrong Repo name: %s", reponame)
		return
	}
	owner = s[0]
	repo = s[1]
	return
}

// returns *github.Repository if passed github repo name
func getGitHubRepo(gitHubClient *github.Client, repoOwner, repoName, githubToken string) (*github.Repository, error) {
	var retried bool
getRepo:
	repo, _, err := gitHubClient.Repositories.Get(context.Background(), repoOwner, repoName)
	if err != nil {
		// retry with authentication
		if gitHubClient = getGHClientWithToken(githubToken); gitHubClient != nil && !retried {
			retried = true
			goto getRepo
		}
		return nil, err
	}
	if repo == nil {
		return nil, errors.Errorf("problem getting repository: %s/%s", repoOwner, repoName)
	}
	return repo, nil
}

// download the git repo to a given path
func (ctr *customTemplateGitHubRepo) cloneRepo(clonePath, githubToken string) error {
	r, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:  ctr.gitCloneURL,
		Auth: ctr.auth,
	})
	if err != nil {
		return errors.Errorf("%s/%s: %s", ctr.owner, ctr.reponame, err.Error())
	}
	// Add the user as well in the config. By default, user is not set
	config, _ := r.Storer.Config()
	config.User.Name = ctr.owner
	return r.SetConfig(config)
}

// performs the git pull on given repo
func (ctr *customTemplateGitHubRepo) pullChanges(repoPath, githubToken string) error {
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	w, err := r.Worktree()
	if err != nil {
		return err
	}
	err = w.Pull(&git.PullOptions{RemoteName: "origin", Auth: ctr.auth})
	if err != nil {
		return errors.Errorf("%s/%s: %s", ctr.owner, ctr.reponame, err.Error())
	}
	return nil
}

// All Custom github repos are cloned in the format of 'owner/reponame' for uniqueness
func (ctr *customTemplateGitHubRepo) getLocalRepoClonePath(downloadPath string) string {
	return filepath.Join(downloadPath, ctr.owner, ctr.reponame)
}

// returns the auth object with username and github token as password
func getAuth(username, password string) *http.BasicAuth {
	if username != "" && password != "" {
		return &http.BasicAuth{Username: username, Password: password}
	}
	return nil
}

// getApplicationAuth creates a basic auth object for the given installation ID and GitHub client
func getApplicationAuth(client *github.Client, installationID int64, ctx context.Context) *http.BasicAuth {
	installation, _, err := client.Apps.CreateInstallationToken(ctx, installationID)
	if err != nil {
		gologger.Fatal().Msgf("Error creating installation token: %s", err)
		return nil
	}

	return &http.BasicAuth{
		Username: "x-access-token",
		Password: installation.GetToken(),
	}
}

func getGHClientWithToken(token string) *github.Client {
	if token != "" {
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		oauthClient := oauth2.NewClient(ctx, ts)
		return github.NewClient(oauthClient)

	}
	return nil
}

func getGHClientIncognito() *github.Client {
	var tc *httpclient.Client
	return github.NewClient(tc)
}

// getGHClientWithAppCertPath creates a GitHub client using the app cert and installation ID.
// It reads the private key from the given path then creates the client, effectively serving as a wrapper around getGHClientWithAppCert
func getGHClientWithAppCertPath(appID int64, installationID int64, privateKeyPath string) *github.Client {
	// Open the file
	file, err := os.Open(privateKeyPath)
	if err != nil {
		gologger.Fatal().Msgf("Failed to open file: %s", err)
		return nil
	}
	defer file.Close()

	// Read in the private key as a []byte array
	privateKey, err := io.ReadAll(file)
	if err != nil {
		gologger.Fatal().Msgf("Error reading private key: %s", err)
		return nil
	}

	// Create the GitHub client with the app cert
	return getGHClientWithAppCert(appID, installationID, privateKey)
}

// getGHClientWithAppCert creates a GitHub client using the app cert and installation ID
func getGHClientWithAppCert(appID int64, installationID int64, privateKey []byte) *github.Client {
	appTokenSource, err := githubauth.NewApplicationTokenSource(appID, privateKey)
	if err != nil {
		gologger.Fatal().Msgf("Error creating application token source: %s", err)
		return nil
	}

	installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)
	httpClient := oauth2.NewClient(context.Background(), installationTokenSource)
	return github.NewClient(httpClient)
}
