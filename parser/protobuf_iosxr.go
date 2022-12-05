package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	"iosxr/telemetry" //vendor import for now
	"github.com/telenornms/skogul"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
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

// IOSXR_Parser
type IOSXR_Parser struct {
	Debug    bool `doc:""`
	Depth    int  `doc:""`
	Stats    *iosxr_statistics
	encoding string
	once     sync.Once
}

type iosxr_statistics struct {
	Received               uint64 // Received parse calls
	Parsed                 uint64 // Successfully parsed packets
	EmptyPayloadsRecieved  uint64 // MDT packets with empty payload
	FailedToJsonUnmarshal  uint64 // JSON payloads unpacked unsuccessfully
	FailedToGpbkvUnmarshal uint64 // Gpbkv payloads unpacked unsuccessfully
}

func (x *IOSXR_Parser) initStats() {
	x.Stats = &iosxr_statistics{
		Received: 0,
	}
}

func (x *IOSXR_Parser) Parse(b []byte) (*skogul.Container, error) {
	x.once.Do(x.initStats)
	atomic.AddUint64(&x.Stats.Received, 1)

	var err error
	var hdr tcpMsgHdr

	if x.Depth == 0 {
		x.Depth = 5
	}

	hdrbuf := bytes.NewReader(b[:12])
	data := b[12:]
	err = binary.Read(hdrbuf, binary.BigEndian, &hdr)

	x.encoding = getEncodeStr(hdr.MsgEncap)

	telem := &telemetry.Telemetry{}
	container := skogul.Container{}
	if x.encoding == "json" {
		xrLog.Debugf("Encoding is JSON")

		err = json.Unmarshal(data, telem)
		container.Metrics, err = x.generateMetricsFromJSON(data)
		if err != nil {
			if x.Debug {
				xrLog.Debugf("Failed to unmarshal json. Data: %v", data)
			}
			atomic.AddUint64(&x.Stats.FailedToJsonUnmarshal, 1)
			return nil, fmt.Errorf("Could not unmarshal JSON payload")
		}
	} else {
		xrLog.Debugf("Encoding is Gpb")

		err = proto.Unmarshal(data, telem)
		xrLog.Debugf("Telem:\n%v", telem)
		if err != nil {
			if x.Debug {
				xrLog.Debugf("Failed to unmarshal protobuf. Data: %v", data)
			}
			atomic.AddUint64(&x.Stats.FailedToGpbkvUnmarshal, 1)
			return nil, fmt.Errorf("Could not unmarshal protobuf payload")
		}

		if telem.GetDataGpb() != nil {
			return nil, fmt.Errorf("Payload from %v:%v was Gpb encoded. Only Gpbkv is currently supported.", telem.GetNodeIdStr(), telem.GetEncodingPath())
		} else if telem.GetDataGpbkv() != nil {
			container.Metrics, err = x.generateDataFromGpbkv(telem)
		} else {
			atomic.AddUint64(&x.Stats.EmptyPayloadsRecieved, 1)
			return nil, fmt.Errorf("Empty Gpb payload recieved from %v, path: %v", telem.GetNodeIdStr(), telem.GetEncodingPath())
		}
	}

	atomic.AddUint64(&x.Stats.Parsed, 1)
	return &container, err
}

// Create and return an array of skogul.Metric type objects containing metrics parsed from
// IOS-XR selfdescribing protobuf-encoded MDT Telemetry packets.
func (x *IOSXR_Parser) generateDataFromGpbkv(telem *telemetry.Telemetry) ([]*skogul.Metric, error) {
	var err error
	var skogulMetrics = make([]*skogul.Metric, 0)

	for _, topField := range telem.GetDataGpbkv() {
		time := time.UnixMilli(int64(telem.GetMsgTimestamp()))
		metric := skogul.Metric{}
		metric.Metadata = x.generateMetaData(telem)
		metric.Data = make(map[string]interface{})
		metric.Time = &time

		//Seems like some endpoints generate empty metrics.
		if len(topField.GetFields()) == 0 {
			atomic.AddUint64(&x.Stats.EmptyPayloadsRecieved, 1)
			return nil, fmt.Errorf("Empty content in Gpbkv payload from %v. Path: %v", metric.Metadata["node_id"], metric.Metadata["encodingPath"])
		}

		//Need to do recursive lookup
		for _, field := range topField.GetFields() {
			if field.Name == "keys" {
				metric.Data["keys"] = createMapRecursive(field.GetFields(), make(map[string]interface{}), x.Depth)
			} else if field.Name == "content" {
				metric.Data["content"] = createMapRecursive(field.GetFields(), make(map[string]interface{}), x.Depth)
			}
		}
		skogulMetrics = append(skogulMetrics, &metric)
	}

	return skogulMetrics, err
}

// The Telemetry Field object contains self references, which means we need a recursive function to map it.
func createMapRecursive(item []*telemetry.TelemetryField, data map[string]interface{}, level int) map[string]interface{} {

	if item == nil || len(item) == 0 {
		return nil
	}

	if level <= 0 {
		xrLog.Warn("Hit max recursive depth.")
		return nil
	}
	//Unsofisticated way to deal with stack overflows. 
	level -= 1
	for _, field := range item {
		var fieldVal interface{}
		children := field.GetFields()
		if children == nil {
			fieldVal = extractGPBKVFieldValueByType(field)
		} else {
			fieldVal = createMapRecursive(children, make(map[string]interface{}), level)
		}
		data[field.Name] = fieldVal
	}
	return data
}

// Return values depending on type.
func extractGPBKVFieldValueByType(field *telemetry.TelemetryField) interface{} {
	switch field.ValueByType.(type) {
	case *telemetry.TelemetryField_BytesValue:
		return field.GetBytesValue()
	case *telemetry.TelemetryField_StringValue:
		return field.GetStringValue()
	case *telemetry.TelemetryField_BoolValue:
		return field.GetBoolValue()
	case *telemetry.TelemetryField_Uint32Value:
		return field.GetUint32Value()
	case *telemetry.TelemetryField_Uint64Value:
		return field.GetUint64Value()
	case *telemetry.TelemetryField_Sint32Value:
		return field.GetSint32Value()
	case *telemetry.TelemetryField_Sint64Value:
		return field.GetSint64Value()
	case *telemetry.TelemetryField_DoubleValue:
		return field.GetDoubleValue()
	case *telemetry.TelemetryField_FloatValue:
		return field.GetFloatValue()
	}
	return nil
}

func (x *IOSXR_Parser) generateMetricsFromJSON(data []byte) ([]*skogul.Metric, error) {
	var jData = make(map[string]interface{})
	var err = json.Unmarshal(data, &jData)
	var skogulMetrics = make([]*skogul.Metric, 0)

	//IOS-XR "metadata" is a common property for multiple metrics.
	metadata, err := x.generateMetadataFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("Could not generate metadata from json: %v", err)
	}

	if jData["data_json"] == nil {
		atomic.AddUint64(&x.Stats.EmptyPayloadsRecieved, 1)
		return nil, fmt.Errorf("Empty content in JSON payload from %v. Path: %v", metadata["node_id"], metadata["encoding_path"])
	}

	//Need to massage the data structure a bit.
	//'data_json' is an array of metric objects.
	for _, obj := range jData["data_json"].([]interface{}) {
		metric := skogul.Metric{}
		metric.Data = make(map[string]interface{})
		metric.Metadata = metadata
		for k, v := range obj.(map[string]interface{}) {
			if k == "timestamp" {
				metric.Time, err = x.parseTimeFromString(v.(string))
			}
			metric.Data[k] = v
		}
		skogulMetrics = append(skogulMetrics, &metric)
	}

	return skogulMetrics, err
}

func (x *IOSXR_Parser) parseTimeFromString(str string) (*time.Time, error) {
	i, err := strconv.ParseInt(str, 10, 64)
	t := time.UnixMilli(i)
	return &t, err
}

func (x *IOSXR_Parser) generateMetadataFromJSON(data []byte) (map[string]interface{}, error) {
	jData := make(map[string]interface{})
	err := json.Unmarshal(data, &jData)
	delete(jData, "data_json")
	return jData, err
}

func (x *IOSXR_Parser) generateMetaData(data *telemetry.Telemetry) map[string]interface{} {
	metadata := make(map[string]interface{})

	metadata["node_id_str"] = data.GetNodeIdStr()
	metadata["encoding_path"] = data.GetEncodingPath()
	metadata["collection_id"] = data.GetCollectionId()
	metadata["msg_timestamp"] = data.GetMsgTimestamp()
	metadata["collection_start_time"] = data.GetCollectionStartTime()
	metadata["subscription_id_str"] = data.GetSubscriptionIdStr()

	return metadata
}

func getEncodeStr(enc encapSTHdrMsgEncap) string {
	switch enc {
	case ENC_ST_HDR_MSG_ENCAP_GPB:
		return "gpb"
	case ENC_ST_HDR_MSG_ENCAP_JSON:
		return "json"
	default:
		return "Unknown"
	}
}
