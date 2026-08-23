module keryx.local/interop/pion

go 1.23

// Direct dependencies (github.com/pion/webrtc/v4, github.com/pion/rtcp) and the full
// dependency graph are resolved and pinned by `go mod tidy`, which the CI job and the
// PionPeer test helper run before `go build`. go.sum is generated the same way.
