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

func main() {
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
	if opts.domain == "" {
		log.Fatalln("Parameter domain is required")
		return
	}
	if opts.realm == "" {
		log.Fatalln("Parameter realm is required")
		return
	}
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
	clientId, clientSecret := readYamlClientIdAndSecret(root, opts.username)
	if opts.clientId == "" {
		if clientId == "" {
			log.Fatalln("Parameter client-id is required")
			return
		}
	} else {
		clientId = opts.clientId
	}
	if opts.clientSecret == "" {
		if clientSecret == "" {
			log.Fatalln("Parameter client-secret is required")
			return
		}
	} else {
		clientSecret = opts.clientSecret
	}
	realmUrl := fmt.Sprintf("https://%s/auth/realms/%s", opts.domain, opts.realm)
	loginUrl := fmt.Sprintf("%s/protocol/openid-connect/token", realmUrl)
	resp, err := login(loginUrl, clientId, clientSecret, opts.username, opts.password)
	if err != nil {
		log.Fatalln(err)
		return
	}
	conf := makeYamlConfig(opts.username, clientId, clientSecret, realmUrl, resp.IdToken, resp.RefreshToken)
	replaceYamlConfig(root, opts.username, conf)
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ret, fmt.Errorf("fail to request login api: %s", resp.Status)
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ret, err
	}
	err = resp.Body.Close()
	if err != nil {
		return ret, err
	}
	err = json.Unmarshal(buf, &ret)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func readYamlClientIdAndSecret(root map[string]interface{}, username string) (string, string) {
	c := readYamlConfig(root, username)
	if c == nil {
		return "", ""
	}
	usr, ok := c["user"]
	if !ok {
		return "", ""
	}
	auth, ok := usr.(map[string]interface{})["auth-provider"]
	if !ok {
		return "", ""
	}
	conf, ok := auth.(map[string]interface{})["config"]
	if !ok {
		return "", ""
	}
	data := conf.(map[string]interface{})
	clientId, ok := data["client-id"]
	if !ok {
		clientId = ""
	}
	clientSecret, ok := data["client-secret"]
	if !ok {
		clientSecret = ""
	}
	return clientId.(string), clientSecret.(string)
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

func makeYamlConfig(username string, clientId string, clientSecret string, idpIssuerUrl string, idToken string, refreshToken string) map[string]interface{} {
	conf := make(map[string]interface{})
	conf["client-id"] = clientId
	conf["client-secret"] = clientSecret
	conf["idp-issuer-url"] = idpIssuerUrl
	conf["id-token"] = idToken
	conf["refresh-token"] = refreshToken
	auth := make(map[string]interface{})
	auth["name"] = "oidc"
	auth["config"] = conf
	usr := make(map[string]interface{})
	usr["auth-provider"] = auth
	root := make(map[string]interface{})
	root["name"] = username
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
