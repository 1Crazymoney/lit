package qln

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/adiabat/btcutil"
	"github.com/mit-dci/lit/lnutil"
)

const minBalHere = 10000 // channels have to have 10K sat in them; can make variable later.

func (nd *LitNode) PushProbChannel(qc *Qchan, amt uint32, numtxs uint8) error {
	fmt.Println("Starting PushProbChannel")
	// sanity checks
	if amt != 1 {
		return fmt.Errorf("can only send exactly one satoshi")
	}

	// see if channel is busy, error if so, lock if not
	// lock this channel

	select {
	case <-qc.ClearToSend:
	// keep going
	default:
		return fmt.Errorf("Channel %d busy", qc.Idx())
	}
	// ClearToSend is now empty

	// reload from disk here, after unlock
	err := nd.ReloadQchanState(qc)
	if err != nil {
		// don't clear to send here; something is wrong with the channel
		return err
	}

	// perform minbal checks after reload
	// check if this push would lower my balance below minBal
	if int64(amt)+minBalHere > qc.State.MyAmt {
		qc.ClearToSend <- true
		return fmt.Errorf("want to maybe push %s but %s available, %s minBal",
			lnutil.SatoshiColor(int64(amt)), lnutil.SatoshiColor(qc.State.MyAmt), lnutil.SatoshiColor(minBal))
	}
	// check if this push is sufficient to get them above minBal
	if (qc.Value-qc.State.MyAmt) < minBalHere {
		qc.ClearToSend <- true
		return fmt.Errorf("insufficient counterparty funds; bal %s minBal %s",
			lnutil.SatoshiColor(qc.Value-qc.State.MyAmt),
			lnutil.SatoshiColor(minBal))
	}

	qc.State.NumTxs = numtxs
	qc.State.ProbAmt = amt
	qc.State.StateIdx++
	qc.State.MyAmt -= int64(qc.State.ProbAmt)
	// save to db with everything changed. this is dumb
	err = nd.SaveQchanState(qc)
	if err != nil {
		// don't clear to send here; something is wrong with the channel
		return err
	}

	err = nd.SendProbInit(qc)
	if err != nil {
		// don't clear; something is wrong with the network
		return err
	}

	fmt.Println("Before the queue")
	
	// update CTS queue
	<-qc.ClearToSend
	qc.ClearToSend <- true

	fmt.Println("Done with PushProbChannel")
	return nil
}

func (nd *LitNode) SendProbInit(q *Qchan) error {
	outMsg := lnutil.NewProbInitMsg(q.Peer(), q.Op, q.State.ProbAmt, q.State.NumTxs)
	nd.OmniOut <- outMsg

	return nil
}

func (nd *LitNode) ProbInitHandler(msg lnutil.ProbInitMsg, qc *Qchan) error {
	numtxs := msg.NumTxs
	probamt := msg.Amt

	// assume we don't have a collision... because sanity is important

	err := nd.ReloadQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbInitHandler ReloadQchan err %s", err.Error())
	}

	// be naive and trust everything
	qc.State.ProbAmt = probamt
	qc.State.NumTxs = numtxs
	qc.State.StateIdx++
	
	for txnum := uint8(8); txnum < qc.State.NumTxs; txnum++ {
		rand.Read(qc.State.RevocPre[txnum][:])
		copy(qc.State.Revoc[txnum][:], btcutil.Hash160(qc.State.RevocPre[txnum][:]))
	}

	err = nd.SaveQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbInitHandler SaveQchanState err %s", err.Error())
	}

	err = nd.SendProbCommit(qc)
	if err != nil {
		return fmt.Errorf("ProbInitHandler SendProbCommit err %s", err.Error())
	}

	return nil
}

func (nd *LitNode) SendProbCommit(q *Qchan) error {
	outMsg := lnutil.NewProbCommitMsg(q.Peer(), q.Op, q.State.Revoc)
	nd.OmniOut <- outMsg

	return nil
}

func (nd *LitNode) ProbCommitHandler(msg lnutil.ProbCommitMsg, qc *Qchan) error {
	revoc := msg.Revoc

	err := nd.ReloadQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbCommitHandler ReloadQchan err %s", err.Error())
	}

	// life is good and adversaries don't actually exist
	qc.State.Revoc = revoc

	err = nd.SaveQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbCommitHandler SaveQchanState err %s", err.Error())
	}

	err = nd.SendProbOffer(qc)
	if err != nil {
		return fmt.Errorf("ProbCommitHandler SendProbOffer err %s", err.Error())
	}

	return nil
}

func (nd *LitNode) SendProbOffer(q *Qchan) error {
	q.State.ElkPoint = q.State.NextElkPoint
	q.State.NextElkPoint = q.State.N2ElkPoint

	fmt.Println(q.State.NumTxs)
	fmt.Println(int64(q.State.NumTxs))
	randInt, err := rand.Int(rand.Reader, big.NewInt(int64(q.State.NumTxs)))
	if err != nil {
		return err
	}
	q.State.Correct = uint8(randInt.Uint64())
	
	rand.Read(q.State.SecretPre[:])
	copy(q.State.Secret[:], btcutil.Hash160(q.State.SecretPre[:20+q.State.Correct]))
	
	sigs, err := nd.SignProbStates(q, true)
	if err != nil {
		return err
	}

	outMsg := lnutil.NewProbOfferMsg(q.Peer(), q.Op, q.State.Secret, sigs)
	nd.OmniOut <- outMsg

	return nil
}

func (nd *LitNode) ProbOfferHandler(msg lnutil.ProbOfferMsg, qc *Qchan) error {
	secret := msg.Secret
	sigs := msg.Sigs

	err := nd.ReloadQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbOfferHandler ReloadQchan err %s", err.Error())
	}

	qc.State.Secret = secret

	randInt, err := rand.Int(rand.Reader, big.NewInt(int64(qc.State.NumTxs)))
	if err != nil {
		return err
	}
	qc.State.Choice = uint8(randInt.Uint64())
	
	// TODO: verify signature
	qc.State.sig = sigs[qc.State.Choice]
	
	err = nd.SaveQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbOfferHandler SaveQchanState err %s", err.Error())
	}

	err = nd.SendProbChoice(qc)

	return nil
}

func (nd *LitNode) SendProbChoice(q *Qchan) error {
	// revoke things!
	elk, err := q.ElkSnd.AtIndex(q.State.StateIdx - 1)
	if err != nil {
		return err
	}

	q.State.ElkPoint = q.State.NextElkPoint

	sigs, err := nd.SignProbStates(q, false)
	if err != nil {
		return err
	}

	sig := sigs[q.State.Choice]

	revocpre := q.State.RevocPre
	rand.Read(revocpre[q.State.Choice][:]) // we don't want to transmit the secret for the committed thing

	n2ElkPoint, err := q.N2ElkPointForThem()
	if err != nil {
		return err
	}

	outMsg := lnutil.NewProbChoiceMsg(q.Peer(), q.Op, q.State.Choice, revocpre, sig, *elk, n2ElkPoint)

	nd.OmniOut <- outMsg
	return nil
}

func (nd *LitNode) ProbChoiceHandler(msg lnutil.ProbChoiceMsg, qc *Qchan) error {
	err := nd.ReloadQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbChoiceHandler ReloadQchan err %s", err.Error())
	}

	// TODO: actually verify this signature
	qc.State.sig = msg.Signature
	
	err = qc.AdvanceElkrem(&msg.Elk, msg.N2ElkPoint)
	if err != nil {
		return fmt.Errorf("ProbChoiceHandler AdvanceElkrem err %s", err.Error())
	}

	// TODO: save, and potentially, use, the prehashes just received
	
	err = nd.SaveQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbChoiceHandler SaveQchanState err %s", err.Error())
	}

	err = nd.SendProbReveal(qc)
	if err != nil {
		return fmt.Errorf("ProbChoiceHandler SendProbReveal err %s", err.Error())
	}

	// done with CTS
	qc.ClearToSend <- true

	return nil
}

func (nd *LitNode) SendProbReveal(q *Qchan) error {
	// revoke things!
	elk, err := q.ElkSnd.AtIndex(q.State.StateIdx - 1)
	if err != nil {
		return err
	}

	n2ElkPoint, err := q.N2ElkPointForThem()
	if err != nil {
		return err
	}

	outMsg := lnutil.NewProbRevealMsg(q.Peer(), q.Op, q.State.Correct, q.State.SecretPre, *elk, n2ElkPoint)

	nd.OmniOut <- outMsg

	return err
}

func (nd *LitNode) ProbRevealHandler(msg lnutil.ProbRevealMsg, qc *Qchan) error {
	err := nd.ReloadQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbRevealHandler ReloadQchan err %s", err.Error())
	}

	err = qc.AdvanceElkrem(&msg.Elk, msg.N2ElkPoint)
	if err != nil {
		return fmt.Errorf("ProbRevealHandler AdvanceElkrem err %s", err.Error())
	}

	err = nd.SaveQchanState(qc)
	if err != nil {
		return fmt.Errorf("ProbRevealHandler SaveQchan err %s", err.Error())
	}

	qc.ClearToSend <- true

	return nil
}
