package parser

import (
	"sync"
	"time"
	"bytes"
	"strconv"
	"encoding/binary"
	"encoding/json"
	"github.com/golang/protobuf/proto"
	"github.com/telenornms/skogul"
	"github.com/ios-xr/telemetry-go-collector/telemetry"
)

var xrLog = skogul.Logger("parser", "iosxr")

type encapSTHdrMsgType uint16
const (
      ENC_ST_HDR_MSG_TYPE_UNSED encapSTHdrMsgType = iota
      ENC_ST_HDR_MSG_TYPE_TELEMETRY_DATA
      ENC_ST_HDR_MSG_TYPE_HEARTBEAT
)

type encapSTHdrMsgEncap uint16
const (
      ENC_ST_HDR_MSG_ENCAP_UNSED encapSTHdrMsgEncap = iota
      ENC_ST_HDR_MSG_ENCAP_GPB
      ENC_ST_HDR_MSG_ENCAP_JSON
)

type tcpMsgHdr struct {
     MsgType       encapSTHdrMsgType
     MsgEncap      encapSTHdrMsgEncap
     MsgHdrVersion uint16
     Msgflag       uint16
     Msglen        uint32
}

type IOSXR_Parser struct {
	Debug bool `doc:""`
	once  sync.Once
	Stats *iosxr_statistics
	Encoding string

}

type iosxr_statistics struct {
	Received                     uint64 // Received parse calls
}

func (x *IOSXR_Parser) initStats() {
	x.Stats = &iosxr_statistics{
		Received:                     0,
	}
}

func (x *IOSXR_Parser) Parse(b []byte) (*skogul.Container, error) {
	x.once.Do(x.initStats)
	var err error
	var hdr tcpMsgHdr

	hdrbuf := bytes.NewReader(b[:12])
	data := b[12:len(b)]
	err = binary.Read(hdrbuf, binary.BigEndian, &hdr)

	x.Encoding = getEncodeStr(hdr.MsgEncap)

	metric := skogul.Metric{}
	telem := &telemetry.Telemetry{}
	container := skogul.Container{}
	if x.Encoding == "json" {
		xrLog.Debugf("Encoding is JSON")
		err = json.Unmarshal(data, telem)
		container.Metrics, err = x.generateMetricsFromJSON(data)
		if err != nil {
			xrLog.Error("Could not genererate metrics from JSON")
		}
	} else {
		xrLog.Debugf("Encoding is GPB")
		err = proto.Unmarshal(data, telem)
		if telem.GetDataGpb() != nil {
			//GPB
		} else {
			//KVGPB
		}
	}

	metric.Metadata, err = x.generateMetaData(telem)

	return &container, err
}

// Create and return an array of skogul.Metric type objects containing metrics parsed from
// IOS-XR protobuf encoded MDT Telemetry packets.
func (x *IOSXR_Parser) generateDataFromGBP(telem *telemetry.Telemetry) ([]*skogul.Metric, error) {
//        var metadata = make(map[string]interface{})
	var skogulMetrics = make([]*skogul.Metric, 0)

	var err error
	return skogulMetrics, err
}

// Create and return an array of skogul.Metric type objects containing metrics parsed from
// IOS-XR selfdescribing protobuf encoded MDT Telemetry packets.
func (x *IOSXR_Parser) generateDataFromGBPKV(telem *telemetry.Telemetry) ([]*skogul.Metric, error) {
//        var metadata = make(map[string]interface{})
        var skogulMetrics = make([]*skogul.Metric, 0)

        var err error

	return skogulMetrics, err
}


func (x *IOSXR_Parser) generateMetricsFromJSON(data []byte) ([]*skogul.Metric, error) {
	var c_data = make(map[string]interface{})
        var err = json.Unmarshal(data, &c_data)
	var skogulMetrics = make([]*skogul.Metric, 0)
	xrLog.Debugf(string(data))
	//IOS-XR "metadata" is a common property for multiple metrics.
	metadata, err := x.generateMetadataFromJSON(data)

	if c_data["data_json"] == nil {
		//empty metrics.
                metric := skogul.Metric{}
                metric.Data = make(map[string]interface{})
                metric.Metadata = metadata
		metric.Time, err = x.parseTimeFromString(c_data["msg_timestamp"].(string))
		skogulMetrics = append(skogulMetrics, &metric)
		return skogulMetrics, err
	}

	//Need to massage the data structure a bit.
	//'data_json' is an array of metric objects.
	for i, obj := range c_data["data_json"].([]interface{}) {
		metric := skogul.Metric{}
		metric.Data = make(map[string]interface{})
		metric.Metadata = metadata
		for k, v := range obj.(map[string]interface{}) {
			if k == "timestamp" {
				metric.Time, err = x.parseTimeFromString(v.(string))
			}
			metric.Data[k] = v
		}
		xrLog.Debugf("Appending metric %v", i)
		skogulMetrics = append(skogulMetrics, &metric)
	}

	return skogulMetrics, err
}

func (x *IOSXR_Parser) parseTimeFromString(time_str string) (*time.Time, error) {
	i, err := strconv.ParseInt(time_str, 10, 64)
	t := time.UnixMilli(i)
	return &t, err
}

func (x *IOSXR_Parser) generateMetadataFromJSON(data []byte) (map[string]interface{}, error) {
        var c_data = make(map[string]interface{})
	var err = json.Unmarshal(data, &c_data)
	delete(c_data, "data_json")
	return c_data, err

}

func (x *IOSXR_Parser) generateMetaData(data *telemetry.Telemetry) (map[string]interface{}, error) {
	var metadata = make(map[string]interface{})

	metadata["nodeId"] = data.GetNodeIdStr()
	metadata["encodingPath"] = data.GetEncodingPath()
	metadata["modelVersion"] = data.GetModelVersion()
	metadata["collectionId"] = data.GetCollectionId()
	metadata["msgTimestamp"] = data.GetMsgTimestamp()
	metadata["collectionStartTime"] = data.GetCollectionStartTime()
	metadata["subscriptionIdStr"] = data.GetSubscriptionIdStr()

	return metadata, nil
}

func getEncodeStr(enc encapSTHdrMsgEncap) string {
     switch (enc) {
     case ENC_ST_HDR_MSG_ENCAP_GPB:
         return "gpb"
     case ENC_ST_HDR_MSG_ENCAP_JSON:
         return "json"
     default:
         return "Unknown"
     }
}
