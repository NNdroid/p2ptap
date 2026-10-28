package node

import (
	"context"
	"io"
	"net"
	"testing"

	yamux "github.com/libp2p/go-yamux/v5"
)

// BenchmarkReadFrameOverYamux measures the framing read cost on a real yamux
// session — the muxer every TCP connection in this overlay runs — rather than
// on a bytes.Reader, because ReadFrame needs two reads per frame (4-byte length
// prefix, then body) and the question is what each of those costs once a muxer
// sits underneath.
//
// Answer, measured: ~1-2% of the frame cost, so leave it alone. Wrapping the
// stream in a 64KiB bufio.Reader — the obvious "one read instead of two"
// optimisation — came out 2-7% SLOWER both over net.Pipe and over a TCP
// loopback (1400B frames, 3s x2). yamux already buffers on the receiving side
// (the session read loop fills a per-stream recvBuf), so the second
// stream.Read is a copy out of memory, not a syscall, and bufio only inserts a
// third copy between the muxer and the frame buffer. That is why handleStream
// reads the stream directly.
//
// The writer drives one WriteFrame per frame, which is what the TX path does,
// so the reader sees the same interleaving as production.
func BenchmarkReadFrameOverYamux(b *testing.B) {
	const frameSize = 1400

	payload := make([]byte, frameSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.SetBytes(frameSize)

	// Real TCP loopback rather than net.Pipe: net.Pipe is synchronous, so its
	// per-write handoff dominates the measurement.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	srvConnCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srvConnCh <- c
	}()
	cliConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	srvConn := <-srvConnCh
	_ = ln.Close()

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard

	// Server side is the reader under test; the client side writes.
	srvSess, err := yamux.Server(srvConn, cfg, nil)
	if err != nil {
		b.Fatalf("yamux server: %v", err)
	}
	cliSess, err := yamux.Client(cliConn, cfg, nil)
	if err != nil {
		b.Fatalf("yamux client: %v", err)
	}
	b.Cleanup(func() {
		_ = srvSess.Close()
		_ = cliSess.Close()
	})

	// Open the stream from the client and accept it on the server. Both halves
	// must be up before either side blocks on I/O.
	srvStreamCh := make(chan *yamux.Stream, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		s, err := srvSess.AcceptStream()
		if err != nil {
			acceptErrCh <- err
			return
		}
		srvStreamCh <- s
	}()
	cliStream, err := cliSess.OpenStream(context.Background())
	if err != nil {
		b.Fatalf("open stream: %v", err)
	}
	var srvStream *yamux.Stream
	select {
	case srvStream = <-srvStreamCh:
	case err := <-acceptErrCh:
		b.Fatalf("accept stream: %v", err)
	}

	// Writer: pump frames until the benchmark closes the stream.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			if err := WriteFrame(cliStream, payload); err != nil {
				return
			}
		}
	}()
	b.Cleanup(func() {
		_ = cliStream.Close()
		<-writerDone
	})

	buf := make([]byte, maxFrameLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := ReadFrame(srvStream, buf)
		if err != nil {
			b.Fatalf("read frame %d: %v", i, err)
		}
		if n != frameSize {
			b.Fatalf("frame %d: got %d bytes, want %d", i, n, frameSize)
		}
	}
	b.StopTimer()
}
