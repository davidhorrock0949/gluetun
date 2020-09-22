package provider

import (
	"fmt"
	"strings"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
)

func filterPIAServers(servers []models.PIAServer, region string) (filtered []models.PIAServer) {
	if len(region) == 0 {
		return servers
	}
	for _, server := range servers {
		if strings.EqualFold(server.Region, region) {
			return []models.PIAServer{server}
		}
	}
	return nil
}

func getPIAOpenVPNConnections(allServers []models.PIAServer, selection models.ServerSelection) (connections []models.OpenVPNConnection, err error) {
	servers := filterPIAServers(allServers, selection.Region)
	if len(servers) == 0 {
		return nil, fmt.Errorf("no server found for region %q", selection.Region)
	}

	var port uint16
	switch selection.Protocol {
	case constants.TCP:
		switch selection.EncryptionPreset {
		case constants.PIAEncryptionPresetNormal:
			port = 502
		case constants.PIAEncryptionPresetStrong:
			port = 501
		}
	case constants.UDP:
		switch selection.EncryptionPreset {
		case constants.PIAEncryptionPresetNormal:
			port = 1198
		case constants.PIAEncryptionPresetStrong:
			port = 1197
		}
	}
	if port == 0 {
		return nil, fmt.Errorf("combination of protocol %q and encryption %q does not yield any port number", selection.Protocol, selection.EncryptionPreset)
	}

	for _, server := range servers {
		for _, IP := range server.IPs {
			if selection.TargetIP != nil {
				if selection.TargetIP.Equal(IP) {
					return []models.OpenVPNConnection{{IP: IP, Port: port, Protocol: selection.Protocol}}, nil
				}
			} else {
				connections = append(connections, models.OpenVPNConnection{IP: IP, Port: port, Protocol: selection.Protocol})
			}
		}
	}

	if selection.TargetIP != nil {
		return nil, fmt.Errorf("target IP %s not found in IP addresses", selection.TargetIP)
	}

	if len(connections) > 64 {
		connections = connections[:64]
	}

	return connections, nil
}

func buildPIAConf(connections []models.OpenVPNConnection, verbosity int, root bool, cipher, auth string, extras models.ExtraConfigOptions) (lines []string) {
	var X509CRL, certificate string
	if extras.EncryptionPreset == constants.PIAEncryptionPresetNormal {
		if len(cipher) == 0 {
			cipher = "aes-128-cbc"
		}
		if len(auth) == 0 {
			auth = "sha1"
		}
		X509CRL = constants.PiaX509CRLNormal
		certificate = constants.PIACertificateNormal
	} else { // strong encryption
		if len(cipher) == 0 {
			cipher = aes256cbc
		}
		if len(auth) == 0 {
			auth = "sha256"
		}
		X509CRL = constants.PiaX509CRLStrong
		certificate = constants.PIACertificateStrong
	}
	lines = []string{
		"client",
		"dev tun",
		"nobind",
		"persist-key",
		"remote-cert-tls server",

		// PIA specific
		"ping 300", // Ping every 5 minutes to prevent a timeout error
		"reneg-sec 0",
		"compress", // allow PIA server to choose the compression to use

		// Added constant values
		"auth-nocache",
		"mute-replay-warnings",
		"pull-filter ignore \"auth-token\"", // prevent auth failed loops
		"auth-retry nointeract",
		"remote-random",
		"suppress-timestamps",

		// Modified variables
		fmt.Sprintf("verb %d", verbosity),
		fmt.Sprintf("auth-user-pass %s", constants.OpenVPNAuthConf),
		fmt.Sprintf("proto %s", connections[0].Protocol),
		fmt.Sprintf("cipher %s", cipher),
		fmt.Sprintf("auth %s", auth),
	}
	if strings.HasSuffix(cipher, "-gcm") {
		lines = append(lines, "ncp-disable")
	}
	if !root {
		lines = append(lines, "user nonrootuser")
	}
	for _, connection := range connections {
		lines = append(lines, fmt.Sprintf("remote %s %d", connection.IP, connection.Port))
	}
	lines = append(lines, []string{
		"<crl-verify>",
		"-----BEGIN X509 CRL-----",
		X509CRL,
		"-----END X509 CRL-----",
		"</crl-verify>",
	}...)
	lines = append(lines, []string{
		"<ca>",
		"-----BEGIN CERTIFICATE-----",
		certificate,
		"-----END CERTIFICATE-----",
		"</ca>",
		"",
	}...)
	return lines
}
