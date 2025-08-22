package linux

import (
	"mini-pqc/scan"
)

// Version variable to store the application version
var Version string

// RunAllCommands executes all available scan commands and returns combined recommendations
func RunAllCommands(jsonOutput bool) []scan.Recommendation {
	var allRecommendations []scan.Recommendation

	// Run all the core scanning modules (excluding Docker)
	allRecommendations = append(allRecommendations, Env(jsonOutput)...)
	allRecommendations = append(allRecommendations, Firmware(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestKernel(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestLib(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestCA(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestRuntime(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestPGP(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestPostfix(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestNginx(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestApache(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestWireguard(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestOpenSSH(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestOpenVPN(jsonOutput)...)
	allRecommendations = append(allRecommendations, TestIPsec(jsonOutput)...)

	return allRecommendations
}
