package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/qdm12/gluetun/internal/models"
)

type piaV4 struct {
	servers            []models.PIAServer
	username, password string
}

func newPrivateInternetAccessV4(servers []models.PIAServer, username, password string) *piaV4 {
	return &piaV4{
		servers:  servers,
		username: username,
		password: password,
	}
}

func (p *piaV4) GetOpenVPNConnections(selection models.ServerSelection) (connections []models.OpenVPNConnection, err error) {
	return getPIAOpenVPNConnections(p.servers, selection)
}

func (p *piaV4) BuildConf(connections []models.OpenVPNConnection, verbosity, uid, gid int, root bool, cipher, auth string, extras models.ExtraConfigOptions) (lines []string) {
	return buildPIAConf(connections, verbosity, root, cipher, auth, extras)
}

func (p *piaV4) GetPortForward(client *http.Client) (port uint16, err error) {
	// TODO persist payload+signature (token+port+expiration date+signature) and only fetch it if not existing
	_, err = fetchToken(p.username, p.password, client)
	if err != nil {
		return 0, fmt.Errorf("cannot obtain token: %w", err)
	}
	// TODO we need the hostname for the current server
	// TODO use https://github.com/pia-foss/manual-connections/blob/master/port_forwarding.sh
	// together with https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
	return 0, fmt.Errorf("not implemented")
}

func fetchToken(username, password string, client *http.Client) (token string, err error) {
	const url = "https://www.privateinternetaccess.com/api/client/v2/token"
	data := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{username, password}
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf(response.Status)
	}
	b, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return "", err
	}
	if len(result.Token) == 0 {
		return "", fmt.Errorf("token is empty")
	}
	return result.Token, nil
}
