package xdptun

import (
	"context"

	"github.com/Crosse/xdp"
	"github.com/getlantern/lantern-cloud/log"
	"github.com/vishvananda/netlink"
)

type Socket struct {
	Queue   int
	Link    netlink.Link
	XDPMode uint32
	Program *xdp.Program
	XSK     *xdp.Socket

	ctx context.Context
}

// newSocket opens a new XDP socket and attaches an XDP program to the NIC.
func newSocket(ctx context.Context, link netlink.Link, queue int, xdpMode uint32, headroom int) (*Socket, error) {
	xdp.DefaultXdpFlags = xdpMode

	program, err := xdp.NewProgram(queue + 1)
	if err != nil {
		return nil, err
	}

	log.Info(ctx, "attaching program")
	if err := program.Attach(link.Attrs().Index); err != nil {
		return nil, err
	}

	options := xdp.SocketOptions{
		NumFrames:              NumFrames,
		FrameSize:              xdp.DefaultSocketOptions.FrameSize,
		FillRingNumDescs:       NumRxDescs,
		CompletionRingNumDescs: NumTxDescs,
		RxRingNumDescs:         NumRxDescs,
		TxRingNumDescs:         NumTxDescs,
		Headroom:               headroom,
	}

	log.Info(ctx, "creating XDP socket")
	xsk, err := xdp.NewSocket(link.Attrs().Index, queue, &options)
	if err != nil {
		return nil, err
	}

	log.Info(ctx, "registering program")
	if err := program.Register(queue, xsk.FD()); err != nil {
		return nil, err
	}

	sock := &Socket{
		Queue:   queue,
		Link:    link,
		XDPMode: xdpMode,
		Program: program,
		XSK:     xsk,
		ctx:     ctx,
	}

	return sock, nil
}

// Close unregisters the XDP program, closes the XDP socket, and detaches the program from the NIC
// It will attempt to perform all operations, but if it encounters an error it will return that at
// the end.
func (s *Socket) Close() error {
	var e error

	log.Info(s.ctx, "unregistering program")
	if err := s.Program.Unregister(s.Queue); err != nil {
		log.Error(s.ctx, "unregistering program", err)
		e = err
	}

	log.Info(s.ctx, "detaching XDP program")
	if err := s.Program.Detach(s.Link.Attrs().Index); err != nil {
		log.Error(s.ctx, "detaching program", err)
		if e == nil {
			e = err
		}
	} else {
		log.Info(s.ctx, "XDP program detached")
	}

	log.Info(s.ctx, "closing socket")
	if err := s.XSK.Close(); err != nil {
		log.Error(s.ctx, "closing socket", err)
		if e == nil {
			e = err
		}
	}

	return e
}
