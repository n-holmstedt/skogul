/*
 * skogul, nats jetstream pushbased receiver
 *
 * Author(s):
 *  - Niklas Holmstedt <n.holmstedt@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 */

package receiver

import (
	"crypto/tls"
	"fmt"
	"github.com/choria-io/fisk"
	"github.com/nats-io/nats.go"
	"github.com/telenornms/skogul"
	"strings"
	"sync"
	"time"
)

var jsLog = skogul.Logger("receiver", "nats")

/*
JetstreamPush consumer:
- Push-based: The Nats server pushes new messages to the receiver.
- Authentication: Username/Password, TLS.
- Authorization: Username/Password, UserCredentials/JWT.
- Durable: If the "ConsumerName" property is set, this receiver will be
considered durable. This means that it will continue to recieve messages
where it left off. Note: If this is combined with a consumer group both
will neither can be changed in order to resume the stream.
- Ephemeral: If the "ConsumerName" property is not set, this receiver
will be considered ephemeral. This means that configured delivery
guarantees are still honored, but it will not be able to resume the stream.
- DeliverGroup: Load balancing for multiple receivers in the same "Queue".

You can also create your consumer separately, with full access to the
consumer API, and reference this in
*/
type JetstreamPush struct {
	Handler       skogul.HandlerRef `doc:"Handler used to parse, transform and send data."`
	Servers       string            `doc:"Comma separated list of nats URLs"`
	StreamName    string            `doc:"Stream name to recieve messages from"`
	DeliverGroup  string            `doc:"Worker queue to distribute messages on"`
	ConsumerName  string            `doc:"Enables resuming where left of, otherwise considered ephemeral"`
	DeliverLast   bool              `doc:"When first consuming messages, the latest message published in the stream will be sent."`
	DeliverAll    bool              `doc:"When first consuming messages, all messages in the stream will be sent."`
	DeliverNew    bool              `doc:"When first consuming messages, only messages created after the consumer was created will be sent."`
	DeliverSeq    uint64            `doc:"When first consuming messages, start with message at this position"`
	DeliverSince  string            `doc:"When first consuming messages, deliver message since a period ago, ex '1m', '200s'"`
	AckPolicy     string            `doc:"'explicit' or 'none', defaults to 'none'."`
	AckWait       string            `doc:"Duration the server will wait for acknowledgement, ex '1s', '200ms'"`
	MaxAckPending int               `doc:"-1 to N. Maximum messages pushed without acknowledgement."`
	FilterSubject string            `doc:"Filter stream by subject"`
	Name          string            `doc:"Client name"`
	Username      string            `doc:"Client username"`
	Password      string            `doc:"Client password"`
	TLSClientKey  string            `doc:"TLS client key file path"`
	TLSClientCert string            `doc:"TLS client cert file path"`
	TLSCACert     string            `doc:"CA cert file path"`
	UserCreds     string            `doc:"Nats credentials file path"`
	NKeyFile      string            `doc:"Nats nkey file path"`
	Insecure      bool              `doc:"TLS InsecureSkipVerify"`
	conOpts       *[]nats.Option
	natsCon       *nats.Conn
	stream        nats.JetStreamContext
	jsConsumeOpts nats.ConsumerConfig
	cInfo         *nats.ConsumerInfo
	wg            sync.WaitGroup
}

// Verify configuration
func (js *JetstreamPush) Verify() error {
	if js.Handler.Name == "" {
		return skogul.MissingArgument("Handler")
	}
	if js.StreamName == "" {
		return skogul.MissingArgument("StreamName")
	}
	if js.Servers == "" {
		return skogul.MissingArgument("Servers")
	}
	//User Credentials
	if js.UserCreds != "" && js.NKeyFile != "" {
		//Cred file contains nkey.
		return fmt.Errorf("Please configure usercreds or nkeyfile.")
	}
	if js.ConsumerName == "" {
		jsLog.Info("Jetstream - Creating ephemeral consumer")
	} else {
		jsLog.Info("Jetstream - Creating durable consumer")
	}
	return nil
}

func (js *JetstreamPush) Start() error {
	if js.Name == "" {
		js.Name = "skogul-jetstream"
	}
	var err error
	js.conOpts = &[]nats.Option{nats.Name(js.Name)}

	// Credentials
	if err := js.setCredentials(); err != nil {
		return err
	}

	// TLS Options
	if err := js.setTLS(); err != nil {
		return err
	}

	// Log disconnects
	*js.conOpts = append(*js.conOpts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		jsLog.WithError(err).Error("Got disconnected!")
	}))
	// Log reconnects
	*js.conOpts = append(*js.conOpts, nats.ReconnectHandler(func(nc *nats.Conn) {
		jsLog.Info("Reconnected")
	}))
	// Always try to reconnect
	*js.conOpts = append(*js.conOpts, nats.RetryOnFailedConnect(true))
	// Try to reconnect forever
	*js.conOpts = append(*js.conOpts, nats.MaxReconnects(-1))

	jsLog.Debugf("Connecting to Nats server(s): %v", js.Servers)
	js.natsCon, err = nats.Connect(js.Servers, *js.conOpts...)
	if err != nil {
		jsLog.Errorf("Encountered an error while connecting to Nats: %v", err)
	}

	// Activate Jetstream functionality for the connections
	js.stream, err = js.natsCon.JetStream()
	if err != nil {
		return fmt.Errorf("Could not enable Jetstream for this connection: %v", err)
	}

	// Fetch Jetstream consumer if existing, or create a new.
	if err := js.setConsumer(); err != nil {
		return err
	}

	// Message delivered callback.
	cb := func(msg *nats.Msg) {
		jsLog.Debugf("Received message on %v", msg.Subject)
		if err := js.Handler.H.Handle(msg.Data); err != nil {
			jsLog.WithError(err).Warn("Unable to handle Nats message")
		}
		if js.cInfo.Config.AckPolicy != nats.AckNonePolicy {
			msg.Ack()
		}
		return
	}

	jsLog.Infof("Receiving stream: %v, with consumer: %v", js.cInfo.Stream, js.cInfo.Name)
	js.wg.Add(1)
	if js.DeliverGroup != "" {
		// If a DeliverGroup was provided the Jetstream server will loadbalance
		// the messages to the service within the same DeliverGroup.
		jsLog.Debugf("Subscribing in queued mode")
		if js.ConsumerName != "" {
			// If ConsumerName was provided, the consumer will be considered durable and
			// will be able to resume from last processed message
			js.stream.QueueSubscribe(js.cInfo.Config.DeliverSubject, js.cInfo.Config.DeliverGroup, cb, nats.Bind(js.StreamName, js.ConsumerName))
		} else {
			// If no ConsumerName is provided the consumer is considered ephemeral and will
			// be removed when the service is disconnected.
			jsLog.Debugf("Consuming in ephemeral mode")
			js.stream.QueueSubscribe(js.cInfo.Config.DeliverSubject, js.cInfo.Config.DeliverGroup, cb, nats.BindStream(js.StreamName))
		}
	} else {
		// If no DeliverGroup was specified, the messages will not be load baclanced
		// and this service will receieve all (SubjectFiltered) messages from the stream.
		jsLog.Debugf("Subscribing in non-queued mode")
		if js.ConsumerName != "" {
			// Durable
			js.stream.Subscribe(js.cInfo.Config.DeliverSubject, cb, nats.Bind(js.StreamName, js.ConsumerName))
		} else {
			// Ephemeral
			jsLog.Debugf("Consuming in ephemeral mode")
			js.stream.Subscribe(js.cInfo.Config.DeliverSubject, cb, nats.BindStream(js.StreamName))
		}
	}
	js.wg.Wait()
	return err
}

func (js *JetstreamPush) setConsumer() (err error) {
	js.cInfo, err = js.stream.ConsumerInfo(js.StreamName, js.ConsumerName)
	if err != nil {
		jsLog.Debugf("Consumer does not exist, Creating consumer!")
		// Jetstream consumer does not exist, create options.
		if err := js.setConsumerType(); err != nil {
			return err
		}
		// Jetstream Acknowledgement Policy.
		if err := js.setAckPolicy(); err != nil {
			return err
		}
		// Jetstream Deliver Policy.
		if err := js.setDeliverPolicy(); err != nil {
			return err
		}
		// Create Jetstream consumer.
		js.cInfo, err = js.stream.AddConsumer(js.StreamName, &js.jsConsumeOpts)
		if err != nil {
			return fmt.Errorf("Could not create consumer: %v", err)
		}
	}
	return nil
}

func (js *JetstreamPush) setCredentials() (err error) {
	if js.UserCreds != "" {
		*js.conOpts = append(*js.conOpts, nats.UserCredentials(js.UserCreds))
	}
	if js.Username != "" && js.Password != "" {
		if js.TLSClientKey != "" {
			jsLog.Warnf("Using plain text password over a non encrypted transport!")
		}
		*js.conOpts = append(*js.conOpts, nats.UserInfo(js.Username, js.Password))
	}
	if js.NKeyFile != "" {
		opt, err := nats.NkeyOptionFromSeed(js.NKeyFile)
		if err != nil {
			jsLog.Fatal(err)
		}
		*js.conOpts = append(*js.conOpts, opt)
	}
	return nil
}

	
func (js *JetstreamPush) setTLS() (err error) {
	if js.TLSClientKey != "" && js.TLSClientCert != "" {
		cert, err := tls.LoadX509KeyPair(js.TLSClientCert, js.TLSClientKey)
		if err != nil {
			return fmt.Errorf("error parsing X509 certificate/key pair: %v", err)
		}

		cp, err := skogul.GetCertPool(js.TLSCACert)
		if err != nil {
			return fmt.Errorf("Failed to initialize root CA pool")
		}

		config := &tls.Config{
			InsecureSkipVerify: js.Insecure,
			Certificates:       []tls.Certificate{cert},
			RootCAs:            cp,
		}
		*js.conOpts = append(*js.conOpts, nats.Secure(config))
	}
	return nil
}

func (js *JetstreamPush) setConsumerType() (err error) {
	if js.FilterSubject != "" {
		js.jsConsumeOpts.FilterSubject = js.FilterSubject
	}
	//The consumertype that we want (Pull) is inplicitly set by using theese options.
	if js.ConsumerName != "" {
		js.jsConsumeOpts.Durable = js.ConsumerName
		js.jsConsumeOpts.DeliverSubject = js.ConsumerName
	}
	if js.DeliverGroup != "" {
		js.jsConsumeOpts.DeliverGroup = js.DeliverGroup
	}
	return nil
}

func (js *JetstreamPush) setDeliverPolicy() (err error) {
	switch {
	case js.DeliverLast:
		js.jsConsumeOpts.DeliverPolicy = nats.DeliverLastPolicy
	case js.DeliverAll:
		js.jsConsumeOpts.DeliverPolicy = nats.DeliverAllPolicy
	case js.DeliverNew:
		js.jsConsumeOpts.DeliverPolicy = nats.DeliverNewPolicy
	case len(js.DeliverSince) > 0:
		var d time.Duration
		d, err = js.parseDurationString(js.DeliverSince)
		if err != nil {
			return fmt.Errorf("Could not parse option DeliverSince: %v", err)
		}
		start := time.Now().Add(-1 * d)
		jsLog.Info("Subscribing to Jetstream %v beginning with messages %v ago", js.StreamName, js.DeliverSince)
		js.jsConsumeOpts.DeliverPolicy = nats.DeliverByStartTimePolicy
		js.jsConsumeOpts.OptStartTime = &start
	case js.DeliverSeq > 0:
		js.jsConsumeOpts.OptStartSeq = js.DeliverSeq
	}
	return nil
}

func (js *JetstreamPush) setAckPolicy() (err error) {
	switch js.AckPolicy {
	case "explicit":
		js.jsConsumeOpts.AckPolicy = nats.AckExplicitPolicy
	case "all":
		js.jsConsumeOpts.AckPolicy = nats.AckAllPolicy
	default:
		js.jsConsumeOpts.AckPolicy = nats.AckNonePolicy
	}
	if js.AckWait != "" {
		var wait time.Duration
		wait, err = js.parseDurationString(js.AckWait)
		if err != nil {
			return fmt.Errorf("Could not parse option AckWait: %v", err)
		}
		js.jsConsumeOpts.AckWait = wait
	} else {
		js.jsConsumeOpts.AckWait = time.Second
	}
	return nil
}

func (js *JetstreamPush) parseDurationString(dstr string) (dur time.Duration, err error) {
	dstr = strings.TrimSpace(dstr)
	if len(dstr) == 0 {
		return 0, nil
	}

	return fisk.ParseDuration(dstr)
}
