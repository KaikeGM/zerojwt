//go:build !race

package zerojwt

// RaceDetectorEnabled is true when tests are compiled with the -race flag.
const RaceDetectorEnabled = false
const raceDetectorEnabled = false
