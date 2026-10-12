package node

// IceTURNConfig prepares the configured TURN servers for pion's ICE agent and
// returns the usable URLs plus the ICE credential pair they require.
//
// TURN credentials are mandatory in WebRTC, and pion enforces that at
// configuration time with no graceful fallback. ICEServer.validate rejects a
// turn:/turns: URL that has no Username or no Credential with ErrNoTurnCredentials,
// PeerConnection.initConfiguration returns on the FIRST invalid server, and the
// peer connection is never created. So a single anonymous TURN entry does not
// shrink the relay set — it disables every WebRTC dial and every inbound
// answer, including ones that would have succeeded on host or server-reflexive
// candidates alone.
//
// The libp2p transport exposes TURN servers as bare URL strings, so the
// credentials have to be pulled out of the configured URL and supplied
// separately. Two things must be handled at the same time:
//
//   - The query string has to be stripped. pion parses the ICE URL with
//     stun.ParseURI, which returns "invalid query" for any query it does not
//     understand, so "turn:h:3478?username=a&credential=b" fails validation too.
//     The URL is rebuilt from the parsed host:port.
//   - ICE applies one credential pair to every server in a list. A server whose
//     pair differs from the first one would fail with ErrTurnCredentials, so it
//     is left out rather than poisoning the list.
//
// Servers that end up excluded are only excluded from WebRTC ICE. They are
// still used by the QUIC TURN binder, which speaks TURN over its own client and
// is unaffected by pion's validation. dropped reports how many were excluded.
func IceTURNConfig(servers []string) (urls []string, username, credential string, dropped int) {
	for _, s := range servers {
		tc, err := parseTurnURL(s)
		if err != nil || tc.Username == "" || tc.Credential == "" {
			dropped++
			continue
		}
		if username == "" {
			username, credential = tc.Username, tc.Credential
		} else if tc.Username != username || tc.Credential != credential {
			dropped++
			continue
		}
		urls = append(urls, "turn:"+tc.ServerAddr)
	}
	return urls, username, credential, dropped
}
