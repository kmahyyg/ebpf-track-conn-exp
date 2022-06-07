package utils

import "time"

func I8ToStr(input []int8) string {
	data := make([]byte, len(input))
	for i, v := range input {
		data[i] = byte(v)
	}
	return string(data)
}

func TimestampAsStr(ts uint64) string {
	tsTime := time.Unix(int64(ts), int64(0))
	return tsTime.Format(time.RFC3339)
}
