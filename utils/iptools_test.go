package iptools

import (
	"testing"
	"time"
)

func TestCountIP(t *testing.T) {
	data1 := []BlockedIP{
		{
			IpAddress: "8.8.8.8",
			LastSeen:  time.Now(),
		},
		{
			IpAddress: "8.8.8.8",
			LastSeen:  time.Now(),
		},
		{
			IpAddress: "8.8.8.8",
			LastSeen:  time.Now(),
		},
		{
			IpAddress: "8.8.8.8",
			LastSeen:  time.Now(),
		},
	}

	data2 := []BlockedIP{
		{
			IpAddress: "8.8.8.8",
			LastSeen:  time.Now(),
		},
		{
			IpAddress: "8.8.9.8",
			LastSeen:  time.Now(),
		},
		{
			IpAddress: "8.8.8.8",
			LastSeen:  time.Now(),
		},
		{
			IpAddress: "8.8.9.8",
			LastSeen:  time.Now(),
		},
	}

	type testData struct {
		ipList []BlockedIP
		result bool
	}
	myData := []testData{
		{
			ipList: data1,
			result: true,
		},
		{
			ipList: data2,
			result: false,
		},
	}
	for _, v := range myData {
		testResult := CountIP(3, "8.8.8.8", &v.ipList, 2)
		if testResult != v.result {
			t.Errorf("Ожидалось %v, Получено %v", v.result, testResult)
		}
	}
}
