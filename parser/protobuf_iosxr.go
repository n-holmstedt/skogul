package parser

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/ios-xr/telemetry-go-collector/telemetry"
	"github.com/telenornms/skogul"
	"strconv"
	"sync"
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

type IOSXR_Parser struct {
	Debug    bool `doc:""`
	once     sync.Once
	Stats    *iosxr_statistics
	Encoding string
}

type iosxr_statistics struct {
	Received uint64 // Received parse calls
}

func (x *IOSXR_Parser) initStats() {
	x.Stats = &iosxr_statistics{
		Received: 0,
	}
}

func (x *IOSXR_Parser) Parse(b []byte) (*skogul.Container, error) {
	x.once.Do(x.initStats)
	var err error
	var hdr tcpMsgHdr

	hdrbuf := bytes.NewReader(b[:12])
	data := b[12:]
	err = binary.Read(hdrbuf, binary.BigEndian, &hdr)

	x.Encoding = getEncodeStr(hdr.MsgEncap)

	telem := &telemetry.Telemetry{}
	container := skogul.Container{}
	if x.Encoding == "json" {
		xrLog.Debugf("Encoding is JSON")
		err = json.Unmarshal(data, telem)
		container.Metrics, err = x.generateMetricsFromJSON(data)
		if err != nil {
			return nil, fmt.Errorf("Could not generate metrics from JSON")
		}
	} else {
		xrLog.Debugf("Encoding is GPB")
		err = proto.Unmarshal(data, telem)
		if telem.GetDataGpb() != nil {
			//GPB
			return nil, fmt.Errorf("GPB Payloads not supported")
		} else {
			//KVGPB
			container.Metrics, err = x.generateDataFromGpbkv(telem)
		}
	}

	return &container, err
}

// Create and return an array of skogul.Metric type objects containing metrics parsed from
// IOS-XR selfdescribing protobuf encoded MDT Telemetry packets.
func (x *IOSXR_Parser) generateDataFromGpbkv(telem *telemetry.Telemetry) ([]*skogul.Metric, error) {
	var err error
	var skogulMetrics = make([]*skogul.Metric, 0)

	for _, topField := range telem.GetDataGpbkv() {
		time := time.UnixMilli(int64(telem.GetMsgTimestamp()))
		metric := skogul.Metric{}
		metric.Metadata, err = x.generateMetaData(telem)
		metric.Data = make(map[string]interface{})
		metric.Time = &time

		//Seems like some endpoints generate empty metrics.

		//Need to do recursive lookup
		for _, field := range topField.GetFields() {
			fieldData := make(map[string]interface{})
			if field.Name == "keys" {
				metric.Data["keys"] = someRecursiveFunction(field.GetFields(), fieldData)
			} else if field.Name == "content" {
				metric.Data["content"] = someRecursiveFunction(field.GetFields(), fieldData)
			}
		}
		skogulMetrics = append(skogulMetrics, &metric)
	}

	return skogulMetrics, err
}

func someRecursiveFunction(item []*telemetry.TelemetryField, data map[string]interface{}) map[string]interface{} {

	if item == nil || len(item) == 0 {
		return nil
	}

	for _, field := range item {
		var fieldVal interface{}

		children := field.GetFields()
		if children == nil {
			fieldVal = extractGPBKVFieldValueByType(field)
		} else {
			fieldVal = someRecursiveFunction(children, data)
		}
		data[field.Name] = fieldVal
	}
	return data
}

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
		return nil, fmt.Errorf("Data empty in packet from %v. Path: %v", metadata["nodeId"], metadata["encodingPath"])
	}

	//Need to massage the data structure a bit.
	//'data_json' is an array of metric objects.
	for i, obj := range jData["data_json"].([]interface{}) {
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

func (x *IOSXR_Parser) parseTimeFromString(str string) (*time.Time, error) {
	i, err := strconv.ParseInt(str, 10, 64)
	t := time.UnixMilli(i)
	return &t, err
}

func (x *IOSXR_Parser) generateMetadataFromJSON(data []byte) (map[string]interface{}, error) {
	var jData = make(map[string]interface{})
	var err = json.Unmarshal(data, &jData)
	delete(jData, "data_json")
	return jData, err

}

func (x *IOSXR_Parser) generateMetaData(data *telemetry.Telemetry) (map[string]interface{}, error) {
	var metadata = make(map[string]interface{})

	metadata["node_id_str"] = data.GetNodeIdStr()
	metadata["encoding_path"] = data.GetEncodingPath()
	metadata["collection_id"] = data.GetCollectionId()
	metadata["msg_timestamp"] = data.GetMsgTimestamp()
	metadata["collection_start_time"] = data.GetCollectionStartTime()
	metadata["subscription_id_str"] = data.GetSubscriptionIdStr()

	return metadata, nil
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
