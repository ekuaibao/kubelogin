package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os/user"
	"path"
	"strings"
)

const version = "0.1.4"

func main() {
	log.Printf("kubelogin version: %s\n", version)
	// parse options
	usr, err := user.Current()
	if err != nil {
		log.Fatalln(err)
		return
	}
	opts := CliOptions{
		config:       path.Join(usr.HomeDir, ".kube/config"),
		domain:       "",
		clientId:     "",
		clientSecret: "",
		username:     "",
		password:     "",
	}
	flag.StringVar(&opts.config, "config", opts.config, "location of kubeconfig file")
	flag.StringVar(&opts.domain, "domain", opts.domain, "domain of keycloak server")
	flag.StringVar(&opts.realm, "realm", opts.realm, "realm name")
	flag.StringVar(&opts.clientId, "client-id", opts.clientId, "id of openid client")
	flag.StringVar(&opts.clientSecret, "client-secret", opts.clientSecret, "secret of openid client")
	flag.StringVar(&opts.username, "username", opts.username, "username")
	flag.StringVar(&opts.password, "password", opts.password, "password")
	flag.Parse()
	if opts.username == "" {
		log.Fatalln("Parameter username is required")
		return
	}
	if opts.password == "" {
		log.Fatalln("Parameter password is required")
		return
	}
	// read kubeconfig
	data, err := ioutil.ReadFile(opts.config)
	if err != nil {
		log.Fatalln(err)
		return
	}
	var body interface{}
	err = yaml.Unmarshal(data, &body)
	if err != nil {
		log.Fatalln(err)
		return
	}
	body = convert(body)
	root := body.(map[string]interface{})
	uc := readUserConfig(root, opts.username)
	// merge options with original kubeconfig
	ku, err := parseKeycloakUrl(uc.idpIssuerUrl)
	if err != nil {
		log.Fatalln(err)
		return
	}
	if opts.domain != "" {
		ku.domain = opts.domain
	}
	if ku.domain == "" {
		log.Fatalln("Parameter domain is required")
		return
	}
	if opts.realm != "" {
		ku.realm = opts.realm
	}
	if ku.realm == "" {
		log.Fatalln("Parameter realm is required")
		return
	}
	realmUrl := fmt.Sprintf("https://%s/auth/realms/%s", ku.domain, ku.realm)
	if opts.clientId != "" {
		uc.clientId = opts.clientId
	}
	if uc.clientId == "" {
		log.Fatalln("Parameter client-id is required")
		return
	}
	if opts.clientSecret != "" {
		uc.clientSecret = opts.clientSecret
	}
	if uc.clientSecret == "" {
		log.Fatalln("Parameter client-secret is required")
		return
	}
	// login
	loginUrl := fmt.Sprintf("%s/protocol/openid-connect/token", realmUrl)
	resp, err := login(loginUrl, uc.clientId, uc.clientSecret, uc.username, opts.password)
	if err != nil {
		log.Fatalln(err)
		return
	}
	// update kubeconfig
	uc.idpIssuerUrl = realmUrl
	uc.idToken = resp.IdToken
	uc.refreshToken = resp.RefreshToken
	updateYamlConfig(root, uc)
	// save files
	data, err = yaml.Marshal(root)
	if err != nil {
		log.Fatalln(err)
		return
	}
	err = ioutil.WriteFile(opts.config, data, 644)
	if err != nil {
		log.Fatalln(err)
		return
	}
	fmt.Printf("Write to %s\n", opts.config)
	// done
	fmt.Println("Login success.")
}

func login(uri string, clientId string, clientSecret string, username string, password string) (LoginResponse, error) {
	ret := LoginResponse{}
	data := url.Values{
		"grant_type":    {"password"},
		"response_type": {"id_token"},
		"scope":         {"openid"},
		"client_id":     {clientId},
		"client_secret": {clientSecret},
		"username":      {username},
		"password":      {password},
	}
	body := strings.NewReader(data.Encode())
	resp, err := http.Post(uri, "application/x-www-form-urlencoded", body)
	if err != nil {
		return ret, err
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ret, err
	}
	err = resp.Body.Close()
	if err != nil {
		return ret, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		text := string(buf)
		return ret, fmt.Errorf("fail to request login api: %s : %s", resp.Status, text)
	}
	err = json.Unmarshal(buf, &ret)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func parseKeycloakUrl(u string) (KeycloakUrl, error) {
	ku := KeycloakUrl{}
	uri, err := url.Parse(u)
	if err != nil {
		return ku, fmt.Errorf("cannot parse keycloak url: %s : %v", u, err)
	}
	ku.domain = uri.Host
	_, err = fmt.Sscanf(uri.Path, "/auth/realms/%s", &ku.realm)
	if err != nil {
		return ku, fmt.Errorf("cannot parse keycloak url: %s : %v", uri.Path, err)
	}
	return ku, nil
}

func readUserConfig(root map[string]interface{}, username string) UserConfig {
	uc := UserConfig{username: username}
	c := readYamlConfig(root, username)
	if c == nil {
		return uc
	}
	usr, ok := c["user"]
	if !ok {
		return uc
	}
	auth, ok := usr.(map[string]interface{})["auth-provider"]
	if !ok {
		return uc
	}
	conf, ok := auth.(map[string]interface{})["config"]
	if !ok {
		return uc
	}
	data := conf.(map[string]interface{})
	idpIssuerUrl, ok := data["idp-issuer-url"]
	if ok {
		uc.idpIssuerUrl = idpIssuerUrl.(string)
	}
	clientId, ok := data["client-id"]
	if ok {
		uc.clientId = clientId.(string)
	}
	clientSecret, ok := data["client-secret"]
	if ok {
		uc.clientSecret = clientSecret.(string)
	}
	return uc
}

func readYamlConfig(root map[string]interface{}, username string) map[string]interface{} {
	raw, ok := root["users"]
	var users []interface{}
	if ok {
		users = raw.([]interface{})
	} else {
		users = []interface{}{}
	}
	for _, u := range users {
		c := u.(map[string]interface{})
		if c["name"] == username {
			return c
		}
	}
	return nil
}

func updateYamlConfig(root map[string]interface{}, uc UserConfig) {
	conf := makeYamlConfig(uc)
	replaceYamlConfig(root, uc.username, conf)
}

func replaceYamlConfig(root map[string]interface{}, username string, value map[string]interface{}) {
	raw, ok := root["users"]
	var users []interface{}
	if ok {
		users = raw.([]interface{})
	} else {
		users = []interface{}{}
	}
	for i, u := range users {
		if u.(map[string]interface{})["name"] == username {
			users[i] = value
			return
		}
	}
	root["users"] = append(users, value)
}

func makeYamlConfig(uc UserConfig) map[string]interface{} {
	conf := make(map[string]interface{})
	conf["client-id"] = uc.clientId
	conf["client-secret"] = uc.clientSecret
	conf["idp-issuer-url"] = uc.idpIssuerUrl
	conf["id-token"] = uc.idToken
	conf["refresh-token"] = uc.refreshToken
	auth := make(map[string]interface{})
	auth["name"] = "oidc"
	auth["config"] = conf
	usr := make(map[string]interface{})
	usr["auth-provider"] = auth
	root := make(map[string]interface{})
	root["name"] = uc.username
	root["user"] = usr
	return root
}

func convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k.(string)] = convert(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return i
}

type CliOptions struct {
	config       string
	domain       string
	realm        string
	clientId     string
	clientSecret string
	username     string
	password     string
}

type LoginResponse struct {
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

type UserConfig struct {
	username     string
	idpIssuerUrl string
	clientId     string
	clientSecret string
	idToken      string
	refreshToken string
}

type KeycloakUrl struct {
	domain string
	realm  string
}
