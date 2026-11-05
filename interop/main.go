// Command opamp-go-harness puts opamp-go, the OpAMP reference implementation, at the far end of a
// connection with this project's Server or Client (ADR-0011). It decides nothing: the Rust test
// in crates/fleet-agent/tests/interop_opamp_go.rs drives the scenarios and asserts on both ends.
//
// The harness reports what opamp-go sees as one JSON object per line on stdout, and takes
// commands as one JSON object per line on stdin.
//
//	opamp-go-harness client [--request-uid] [--tls ca,cert,key [--force-cert]] <url>
//	    opamp-go's Client, connected to <url>; with --tls it trusts the CA file and offers the
//	    certificate (none when cert and key are empty), over TLS 1.3 alone. Go offers a certificate
//	    only when the Server names its CA as acceptable; --force-cert offers it regardless
//	opamp-go-harness server [--tls cert,key,client-ca]
//	    opamp-go's Server, on 127.0.0.1, any port; with --tls it serves TLS 1.3 alone and requires
//	    a client certificate the client CA issued
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opamp-go/client"
	clienttypes "github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server"
	servertypes "github.com/open-telemetry/opamp-go/server/types"
	"google.golang.org/protobuf/proto"
)

var out = struct {
	sync.Mutex
	enc *json.Encoder
}{enc: json.NewEncoder(os.Stdout)}

// emit writes one event line. Every event carries its name under "event".
func emit(event string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["event"] = event
	out.Lock()
	defer out.Unlock()
	_ = out.enc.Encode(fields)
}

// command is one line on stdin.
type command struct {
	Cmd  string `json:"cmd"`
	Name string `json:"name"`
	Body string `json:"body"`
}

// commands delivers stdin lines until stdin closes, then closes the channel.
func commands() <-chan command {
	ch := make(chan command)
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			var c command
			if err := json.Unmarshal(scanner.Bytes(), &c); err != nil {
				emit("error", map[string]any{"message": "bad command: " + err.Error()})
				continue
			}
			ch <- c
		}
	}()
	return ch
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "client":
		flags := flag.NewFlagSet("client", flag.ExitOnError)
		requestUid := flags.Bool("request-uid", false, "ask the Server for an instance_uid")
		files := flags.String("tls", "", "ca,cert,key")
		force := flags.Bool("force-cert", false, "offer the certificate whatever the Server accepts")
		_ = flags.Parse(os.Args[2:])
		if flags.NArg() != 1 {
			usage()
		}
		var config *tls.Config
		if config, err = clientTLS(*files, *force); err == nil {
			err = runClient(flags.Arg(0), *requestUid, config)
		}
	case "server":
		flags := flag.NewFlagSet("server", flag.ExitOnError)
		files := flags.String("tls", "", "cert,key,client-ca")
		_ = flags.Parse(os.Args[2:])
		var config *tls.Config
		if config, err = serverTLS(*files); err == nil {
			err = runServer(config)
		}
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		emit("error", map[string]any{"message": err.Error()})
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: opamp-go-harness client [--request-uid] [--tls ca,cert,key [--force-cert]] <url>")
	fmt.Fprintln(os.Stderr, "       opamp-go-harness server [--tls cert,key,client-ca]")
	os.Exit(2)
}

// tlsFiles splits a comma-separated list of exactly three paths; empty means no TLS.
func tlsFiles(list string) ([]string, error) {
	if list == "" {
		return nil, nil
	}
	files := strings.Split(list, ",")
	if len(files) != 3 {
		return nil, fmt.Errorf("--tls takes three comma-separated files, got %q", list)
	}
	return files, nil
}

// pool reads a CA certificate file into a pool.
func pool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	certs := x509.NewCertPool()
	if !certs.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificate in %s", file)
	}
	return certs, nil
}

// clientTLS trusts the CA and offers the certificate, on TLS 1.3 alone, as this project's own
// endpoint requires of every peer. Without a certificate it offers none.
func clientTLS(list string, force bool) (*tls.Config, error) {
	files, err := tlsFiles(list)
	if files == nil {
		return nil, err
	}
	roots, err := pool(files[0])
	if err != nil {
		return nil, err
	}
	config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if files[1] == "" && files[2] == "" {
		return config, nil
	}
	identity, err := tls.LoadX509KeyPair(files[1], files[2])
	if err != nil {
		return nil, err
	}
	if force {
		// Offered whatever the Server names as acceptable: without this Go sends nothing for a
		// certificate another CA issued, and the refusal of a foreign certificate goes untested.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &identity, nil
		}
	} else {
		// What a real opamp-go agent configures: Go picks it only if the Server accepts its CA.
		config.Certificates = []tls.Certificate{identity}
	}
	return config, nil
}

// serverTLS serves the certificate and requires one the client CA issued, on TLS 1.3 alone.
func serverTLS(list string) (*tls.Config, error) {
	files, err := tlsFiles(list)
	if files == nil {
		return nil, err
	}
	identity, err := tls.LoadX509KeyPair(files[0], files[1])
	if err != nil {
		return nil, err
	}
	clients, err := pool(files[2])
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{identity},
		ClientCAs:    clients,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		// Every handshake attempt is reported, so a test can tell a refused peer from one that
		// never tried.
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			emit("client_hello", nil)
			return nil, nil
		},
	}, nil
}

// constantBackoff reconnects quickly, so a test that restarts the far end waits seconds, not
// opamp-go's default minutes.
type constantBackoff struct{}

func (constantBackoff) NextBackOff() time.Duration { return 200 * time.Millisecond }

// agentCapabilities is what the harness's Client declares; the test asserts the Server saw
// exactly these.
const agentCapabilities = protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus |
	protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
	protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig |
	protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig |
	protobufs.AgentCapabilities_AgentCapabilities_ReportsHeartbeat

func runClient(url string, requestUid bool, tlsConfig *tls.Config) error {
	var uid clienttypes.InstanceUid
	if _, err := rand.Read(uid[:]); err != nil {
		return err
	}
	uid[6] = (uid[6] & 0x0f) | 0x70 // UUID version 7 layout, as the Baseline recommends
	uid[8] = (uid[8] & 0x3f) | 0x80

	var opamp client.OpAMPClient
	var httpClient *http.Client
	if strings.HasPrefix(url, "ws://") || strings.HasPrefix(url, "wss://") {
		opamp = client.NewWebSocket(stderrLogger{})
	} else {
		opamp = client.NewHTTP(stderrLogger{})
		// opamp-go hands the callbacks no Server capabilities and no flags, so on the plain HTTP
		// transport the harness reads each reply itself before opamp-go does.
		// opamp-go puts its TLS configuration on a transport it clones, which this wrapper is not;
		// the wrapped transport carries it instead.
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsConfig
		httpClient = &http.Client{Transport: replyReader{next: transport}}
	}

	if err := opamp.SetAgentDescription(description("")); err != nil {
		return err
	}
	capabilities := agentCapabilities
	if err := opamp.SetCapabilities(&capabilities); err != nil {
		return err
	}
	if requestUid {
		opamp.SetFlags(protobufs.AgentToServerFlags_AgentToServerFlags_RequestInstanceUid)
	}

	heartbeat := time.Second
	ctx := context.Background()
	settings := clienttypes.StartSettings{
		OpAMPServerURL:    url,
		Client:            httpClient,
		TLSConfig:         websocketTLS(httpClient, tlsConfig),
		InstanceUid:       uid,
		HeartbeatInterval: &heartbeat,
		BackoffPolicy:     func() clienttypes.BackoffPolicy { return constantBackoff{} },
		Callbacks: clienttypes.Callbacks{
			OnConnect: func(ctx context.Context) { emit("connected", nil) },
			OnConnectFailed: func(ctx context.Context, err error) {
				emit("connect_failed", map[string]any{"message": err.Error()})
			},
			OnError: func(ctx context.Context, err *protobufs.ServerErrorResponse) {
				emit("server_error", map[string]any{"message": err.ErrorMessage})
			},
			GetEffectiveConfig: func(ctx context.Context) (*protobufs.EffectiveConfig, error) {
				return &protobufs.EffectiveConfig{ConfigMap: &protobufs.AgentConfigMap{}}, nil
			},
			OnMessage: func(ctx context.Context, msg *clienttypes.MessageData) {
				fields := map[string]any{}
				if msg.RemoteConfig != nil {
					hash := msg.RemoteConfig.ConfigHash
					fields["remote_config_hash"] = hex.EncodeToString(hash)
					names := []string{}
					if msg.RemoteConfig.Config != nil {
						for name := range msg.RemoteConfig.Config.ConfigMap {
							names = append(names, name)
						}
					}
					fields["remote_config_names"] = names
					_ = opamp.SetRemoteConfigStatus(&protobufs.RemoteConfigStatus{
						LastRemoteConfigHash: hash,
						Status:               protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED,
					})
				}
				if msg.AgentIdentification != nil {
					fields["new_instance_uid"] = hex.EncodeToString(msg.AgentIdentification.NewInstanceUid)
				}
				emit("message", fields)
			},
			SaveRemoteConfigStatus: func(ctx context.Context, status *protobufs.RemoteConfigStatus) {},
		},
	}
	if err := opamp.Start(ctx, settings); err != nil {
		return err
	}
	emit("started", map[string]any{"instance_uid": hex.EncodeToString(uid[:])})

	for c := range commands() {
		switch c.Cmd {
		case "stop":
			stopCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := opamp.Stop(stopCtx)
			cancel()
			if err != nil {
				emit("stopped", map[string]any{"error": err.Error()})
			} else {
				emit("stopped", nil)
			}
			return nil
		case "describe":
			// A changed description, sent once and then omitted: what a Server that missed it can
			// only learn through ReportFullState.
			if err := opamp.SetAgentDescription(description(c.Body)); err != nil {
				return err
			}
			emit("described", map[string]any{"mark": c.Body})
		default:
			emit("error", map[string]any{"message": "unknown client command " + c.Cmd})
		}
	}
	return nil
}

// websocketTLS is the TLS configuration opamp-go applies itself: on the WebSocket transport alone,
// since on plain HTTP the harness's own transport carries it.
func websocketTLS(httpClient *http.Client, config *tls.Config) *tls.Config {
	if httpClient != nil {
		return nil
	}
	return config
}

// replyReader reports the capabilities and flags of every ServerToAgent a plain HTTP exchange
// returns, then hands opamp-go the body unchanged.
type replyReader struct{ next http.RoundTripper }

func (r replyReader) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var reply protobufs.ServerToAgent
	if resp.Header.Get("Content-Encoding") == "" && proto.Unmarshal(body, &reply) == nil {
		emit("server_reply", map[string]any{
			"capabilities": reply.Capabilities,
			"flags":        reply.Flags,
		})
	}
	return resp, nil
}

// description is the harness Client's AgentDescription; a non-empty mark rides along as the
// non-identifying attribute interop.mark.
func description(mark string) *protobufs.AgentDescription {
	nonIdentifying := []*protobufs.KeyValue{stringAttr("os.type", "linux")}
	if mark != "" {
		nonIdentifying = append(nonIdentifying, stringAttr("interop.mark", mark))
	}
	return &protobufs.AgentDescription{
		IdentifyingAttributes:    []*protobufs.KeyValue{stringAttr("service.name", "opamp-go-harness")},
		NonIdentifyingAttributes: nonIdentifying,
	}
}

func stringAttr(key, value string) *protobufs.KeyValue {
	return &protobufs.KeyValue{
		Key:   key,
		Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: value}},
	}
}

// serverCapabilities is what the harness's Server declares on every reply until a "capabilities"
// command changes it.
const serverCapabilities = protobufs.ServerCapabilities_ServerCapabilities_AcceptsStatus |
	protobufs.ServerCapabilities_ServerCapabilities_OffersRemoteConfig |
	protobufs.ServerCapabilities_ServerCapabilities_AcceptsEffectiveConfig

// pending holds what the next reply carries, set by stdin commands and consumed by one reply.
type pending struct {
	sync.Mutex
	remoteConfig    *protobufs.AgentRemoteConfig
	reportFullState bool
	newUid          []byte
	capabilities    uint64
}

func runServer(tlsConfig *tls.Config) error {
	next := pending{capabilities: uint64(serverCapabilities)}
	srv := server.New(nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	settings := server.StartSettings{
		Listener:   listener,
		ListenPath: "/v1/opamp",
		TLSConfig:  tlsConfig,
		Settings: server.Settings{
			Callbacks: servertypes.Callbacks{
				OnConnecting: func(r *http.Request) servertypes.ConnectionResponse {
					return servertypes.ConnectionResponse{
						Accept: true,
						ConnectionCallbacks: servertypes.ConnectionCallbacks{
							OnMessage: func(
								ctx context.Context, conn servertypes.Connection, msg *protobufs.AgentToServer,
							) *protobufs.ServerToAgent {
								return onAgentMessage(&next, msg)
							},
						},
					}
				},
			},
		},
	}
	if err := srv.Start(settings); err != nil {
		return err
	}
	emit("listening", map[string]any{"port": listener.Addr().(*net.TCPAddr).Port})

	for c := range commands() {
		next.Lock()
		switch c.Cmd {
		case "offer_config":
			body := []byte(c.Body)
			hash := make([]byte, 32)
			if _, err := rand.Read(hash); err != nil {
				next.Unlock()
				return err
			}
			next.remoteConfig = &protobufs.AgentRemoteConfig{
				Config: &protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigObject{
					c.Name: {Body: body},
				}},
				ConfigHash: hash,
			}
			emit("queued", map[string]any{"cmd": c.Cmd, "hash": hex.EncodeToString(hash)})
		case "capabilities":
			var value uint64
			if _, err := fmt.Sscan(c.Body, &value); err != nil {
				next.Unlock()
				return err
			}
			next.capabilities = value
			emit("queued", map[string]any{"cmd": c.Cmd})
		case "report_full_state":
			next.reportFullState = true
			emit("queued", map[string]any{"cmd": c.Cmd})
		case "new_uid":
			uid := make([]byte, 16)
			if _, err := rand.Read(uid); err != nil {
				next.Unlock()
				return err
			}
			uid[6] = (uid[6] & 0x0f) | 0x70
			uid[8] = (uid[8] & 0x3f) | 0x80
			next.newUid = uid
			emit("queued", map[string]any{"cmd": c.Cmd, "uid": hex.EncodeToString(uid)})
		case "stop":
			next.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Stop(ctx)
		default:
			emit("error", map[string]any{"message": "unknown server command " + c.Cmd})
		}
		next.Unlock()
	}
	return nil
}

// onAgentMessage reports one AgentToServer and builds the reply, carrying whatever a command
// queued for it.
func onAgentMessage(next *pending, msg *protobufs.AgentToServer) *protobufs.ServerToAgent {
	fields := map[string]any{
		"instance_uid":         hex.EncodeToString(msg.InstanceUid),
		"sequence_num":         msg.SequenceNum,
		"capabilities":         msg.Capabilities,
		"flags":                msg.Flags,
		"has_description":      msg.AgentDescription != nil,
		"agent_disconnect":     msg.AgentDisconnect != nil,
		"has_effective_config": msg.EffectiveConfig != nil,
	}
	if d := msg.AgentDescription; d != nil {
		for _, kv := range d.IdentifyingAttributes {
			if kv.Key == "service.name" {
				fields["service_name"] = kv.Value.GetStringValue()
			}
		}
	}
	if s := msg.RemoteConfigStatus; s != nil {
		fields["remote_config_status"] = s.Status.String()
		fields["remote_config_hash"] = hex.EncodeToString(s.LastRemoteConfigHash)
	}
	emit("agent_message", fields)

	next.Lock()
	defer next.Unlock()
	reply := &protobufs.ServerToAgent{
		InstanceUid:  msg.InstanceUid,
		Capabilities: next.capabilities,
	}
	if next.remoteConfig != nil {
		reply.RemoteConfig = next.remoteConfig
		next.remoteConfig = nil
		emit("sent", map[string]any{"what": "remote_config"})
	}
	if next.reportFullState {
		reply.Flags |= uint64(protobufs.ServerToAgentFlags_ServerToAgentFlags_ReportFullState)
		next.reportFullState = false
		emit("sent", map[string]any{"what": "report_full_state"})
	}
	if next.newUid != nil {
		reply.AgentIdentification = &protobufs.AgentIdentification{NewInstanceUid: next.newUid}
		next.newUid = nil
		emit("sent", map[string]any{"what": "agent_identification"})
	}
	return reply
}

// stderrLogger passes opamp-go's own errors to stderr, where a failing run shows them beside ours.
type stderrLogger struct{}

func (stderrLogger) Debugf(ctx context.Context, format string, v ...any) {}

func (stderrLogger) Errorf(ctx context.Context, format string, v ...any) {
	fmt.Fprintf(os.Stderr, "opamp-go error: "+format+"\n", v...)
}
