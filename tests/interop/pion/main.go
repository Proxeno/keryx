// Command pion-peer is the Go/pion reference-implementation peer the Keryx PionInterop
// integration tests drive, the non-browser counterpart to assets/chrome-client.html.
//
// It mirrors the Chrome fixture's default role (role=answer): Keryx is the offerer and
// this peer answers. Over a tiny HTTP signaling shim it:
//
//	GET  /offer   -> { type: "offer",  sdp }   (Keryx is the offerer)
//	POST /answer  <- { type: "answer", sdp }   (posted once ICE gathering completes)
//	POST /report  <- periodic JSON status snapshots the test asserts on
//
// It exercises media and a data channel in both directions in a single handshake:
//   - Media: it receives Keryx's sendonly H.264 track and counts inbound RTP packets and
//     frames (marker bits), and periodically sends a Picture Loss Indication so Keryx emits
//     a keyframe it can lock onto.
//   - Data: it accepts the data channels Keryx opens ("controller", "telemetry") and echoes
//     every "ping:N" back as "echo:N", so a message round-trips Keryx -> pion -> Keryx.
//
// The ICE/DTLS-SRTP path is pinned to 127.0.0.1 loopback host candidates only (no STUN/TURN,
// no mDNS), so it runs on a headless CI runner exactly like the Chrome job.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

// channelStat records what one data channel has seen, for the report the test asserts on.
type channelStat struct {
	ReadyState string `json:"readyState"`
	Received   uint64 `json:"received"`
	Echoed     uint64 `json:"echoed"`
}

// report is the JSON snapshot POSTed to /report; field names match PionInteropTests.
type report struct {
	Phase           string `json:"phase"`
	Role            string `json:"role"`
	ConnectionState string `json:"connectionState"`
	ICEState        string `json:"iceConnectionState"`
	Video           struct {
		PacketsReceived uint64 `json:"packetsReceived"`
		FramesReceived  uint64 `json:"framesReceived"`
		BytesReceived   uint64 `json:"bytesReceived"`
		SSRC            uint32 `json:"ssrc"`
	} `json:"video"`
	Track    struct {
		Video bool `json:"video"`
		Audio bool `json:"audio"`
	} `json:"track"`
	Channels map[string]*channelStat `json:"channels"`
	Error    string                  `json:"error,omitempty"`
}

// state is the peer's shared, concurrently-updated view, serialized into a report.
type state struct {
	mu sync.Mutex

	phase           string
	connectionState string
	iceState        string
	errText         string

	trackVideo bool
	trackAudio bool
	videoSSRC  uint32

	packetsReceived atomic.Uint64
	framesReceived  atomic.Uint64
	bytesReceived   atomic.Uint64

	channels map[string]*channelStat
}

func newState(role string) *state {
	s := &state{channels: map[string]*channelStat{}}
	s.phase = "boot"
	s.connectionState = "new"
	s.iceState = "new"
	_ = role
	return s
}

func (s *state) setPhase(p string) {
	s.mu.Lock()
	s.phase = p
	s.mu.Unlock()
}

func (s *state) snapshot(role string) report {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r report
	r.Phase = s.phase
	r.Role = role
	r.ConnectionState = s.connectionState
	r.ICEState = s.iceState
	r.Error = s.errText
	r.Track.Video = s.trackVideo
	r.Track.Audio = s.trackAudio
	r.Video.PacketsReceived = s.packetsReceived.Load()
	r.Video.FramesReceived = s.framesReceived.Load()
	r.Video.BytesReceived = s.bytesReceived.Load()
	r.Video.SSRC = s.videoSSRC
	r.Channels = map[string]*channelStat{}
	for k, v := range s.channels {
		cp := *v
		r.Channels[k] = &cp
	}
	return r
}

func main() {
	signal := flag.String("signal", "http://127.0.0.1:7984", "base URL of the test signaling host")
	role := flag.String("role", "answer", "peer role; only 'answer' (Keryx offers) is implemented")
	portMin := flag.Int("port-min", 7800, "lowest UDP port to bind for ICE host candidates")
	portMax := flag.Int("port-max", 7899, "highest UDP port to bind for ICE host candidates")
	flag.Parse()

	if *role != "answer" {
		log.Fatalf("unsupported role %q: only 'answer' is implemented", *role)
	}

	st := newState(*role)

	pc, err := newPeerConnection(uint16(*portMin), uint16(*portMax))
	if err != nil {
		log.Fatalf("create peer connection: %v", err)
	}
	defer func() { _ = pc.Close() }()

	wireCallbacks(pc, st)

	// Periodic report pump: the test polls these snapshots.
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		for {
			postJSON(client, *signal+"/report", st.snapshot(*role))
			time.Sleep(200 * time.Millisecond)
		}
	}()

	if err := runAnswerer(pc, st, *signal); err != nil {
		st.mu.Lock()
		st.errText = err.Error()
		st.phase = "failed"
		st.mu.Unlock()
		log.Fatalf("answerer flow: %v", err)
	}

	// Keep the process alive, receiving media and echoing data, until the test kills it.
	select {}
}

// newPeerConnection builds an API pinned to 127.0.0.1 loopback host candidates and constructs a
// PeerConnection with no ICE servers, so DTLS-SRTP/ICE stays a pure loopback path.
func newPeerConnection(portMin, portMax uint16) (*webrtc.PeerConnection, error) {
	s := webrtc.SettingEngine{}
	// Loopback only: include the loopback candidate that pion excludes by default, then filter
	// every other IP out so 127.0.0.1 is the sole host candidate (no STUN/TURN, no mDNS).
	s.SetIncludeLoopbackCandidate(true)
	s.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
	s.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	if err := s.SetEphemeralUDPPortRange(portMin, portMax); err != nil {
		return nil, err
	}

	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}

	api := webrtc.NewAPI(webrtc.WithSettingEngine(s), webrtc.WithMediaEngine(m))
	return api.NewPeerConnection(webrtc.Configuration{})
}

// wireCallbacks attaches the connection-state, track, and data-channel handlers.
func wireCallbacks(pc *webrtc.PeerConnection, st *state) {
	pc.OnConnectionStateChange(func(cs webrtc.PeerConnectionState) {
		st.mu.Lock()
		st.connectionState = cs.String()
		st.mu.Unlock()
	})
	pc.OnICEConnectionStateChange(func(cs webrtc.ICEConnectionState) {
		st.mu.Lock()
		st.iceState = cs.String()
		st.mu.Unlock()
	})

	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		st.mu.Lock()
		if track.Kind() == webrtc.RTPCodecTypeVideo {
			st.trackVideo = true
			st.videoSSRC = uint32(track.SSRC())
		} else {
			st.trackAudio = true
		}
		st.mu.Unlock()

		if track.Kind() != webrtc.RTPCodecTypeVideo {
			return
		}

		ssrc := uint32(track.SSRC())
		// Ask Keryx for a keyframe until frames flow: Keryx restarts its H.264 asset from its
		// opening IDR when it sees a PLI, so a mid-stream joiner can lock on.
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for range ticker.C {
				if st.framesReceived.Load() > 5 {
					return
				}
				_ = pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: ssrc}})
			}
		}()

		for {
			pkt, _, err := track.ReadRTP()
			if err != nil {
				return
			}
			st.packetsReceived.Add(1)
			st.bytesReceived.Add(uint64(len(pkt.Payload)))
			if pkt.Marker {
				st.framesReceived.Add(1)
			}
		}
	})

	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		entry := &channelStat{ReadyState: dc.ReadyState().String()}
		st.mu.Lock()
		st.channels[dc.Label()] = entry
		st.mu.Unlock()

		dc.OnOpen(func() {
			st.mu.Lock()
			entry.ReadyState = dc.ReadyState().String()
			st.mu.Unlock()
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			st.mu.Lock()
			entry.Received++
			st.mu.Unlock()
			if !msg.IsString {
				return
			}
			text := string(msg.Data)
			if strings.HasPrefix(text, "ping:") {
				if err := dc.SendText("echo:" + text[len("ping:"):]); err == nil {
					st.mu.Lock()
					entry.Echoed++
					st.mu.Unlock()
				}
			}
		})
	})
}

// runAnswerer performs the JSEP answerer flow against the HTTP signaling host: fetch Keryx's
// offer, answer it, gather ICE fully, and post the answer with candidates embedded.
func runAnswerer(pc *webrtc.PeerConnection, st *state, signal string) error {
	client := &http.Client{Timeout: 5 * time.Second}

	st.setPhase("fetching-offer")
	offerSDP, err := fetchOffer(client, signal+"/offer")
	if err != nil {
		return err
	}

	st.setPhase("set-remote")
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offerSDP,
	}); err != nil {
		return err
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return err
	}

	// Vanilla ICE: complete gathering before signaling so candidates ride in the SDP.
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	st.setPhase("gathering")
	if err := pc.SetLocalDescription(answer); err != nil {
		return err
	}
	<-gatherComplete

	st.setPhase("posting-answer")
	local := pc.LocalDescription()
	if err := postAnswer(client, signal+"/answer", local.SDP); err != nil {
		return err
	}

	st.setPhase("negotiated")
	return nil
}

// fetchOffer GETs the offer with a short retry, in case the peer starts before the host binds.
func fetchOffer(client *http.Client, url string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 40; attempt++ {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		var payload struct {
			Type string `json:"type"`
			SDP  string `json:"sdp"`
		}
		err = json.NewDecoder(resp.Body).Decode(&payload)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if payload.SDP == "" {
			lastErr = errEmptyOffer
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return payload.SDP, nil
	}
	return "", lastErr
}

func postAnswer(client *http.Client, url, sdp string) error {
	body, err := json.Marshal(map[string]string{"type": "answer", "sdp": sdp})
	if err != nil {
		return err
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func postJSON(client *http.Client, url string, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		return
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

type errString string

func (e errString) Error() string { return string(e) }

const errEmptyOffer = errString("offer SDP was empty")
