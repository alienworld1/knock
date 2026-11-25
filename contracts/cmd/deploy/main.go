package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"knock/internal/chain"
	"knock/internal/command"

	"github.com/spf13/cobra"
)

func main() {
	var profile string
	var artifact string
	cmd := &cobra.Command{
		Use: "deploy", Short: "Deploy KnockRegistry to Diana", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := os.Stat(artifact)
			if err != nil {
				return command.Exit(2, err)
			}
			if !info.Mode().IsRegular() || info.Size() > 1<<20 {
				return command.Exit(2, errors.New("expected a KnockRegistry Foundry artifact"))
			}
			data, err := os.ReadFile(artifact)
			if err != nil {
				return command.Exit(8, err)
			}
			var build struct {
				Bytecode struct{ Object string }
			}
			if err := json.Unmarshal(data, &build); err != nil {
				return command.Exit(2, err)
			}
			code, err := hex.DecodeString(strings.TrimPrefix(build.Bytecode.Object, "0x"))
			if err != nil || len(code) == 0 {
				return command.Exit(2, errors.New("artifact has no valid deployment bytecode"))
			}
			keys, err := command.Unlock(command.Profile(command.Home(), profile), "Owner passphrase")
			if err != nil {
				return command.Exit(8, err)
			}
			defer keys.Clear()
			ctx, cancel := context.WithTimeout(cmd.Context(), 100*time.Second)
			defer cancel()
			client, err := chain.Connect(ctx, chain.Diana())
			if err != nil {
				return command.Exit(3, err)
			}
			defer client.Close()
			address, hash, err := client.Deploy(ctx, keys, code, command.Progress)
			if err != nil {
				return command.Exit(3, err)
			}
			return command.Exit(8, json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Registry chain.Registry `json:"registry"`
			}{chain.Registry{Address: address, CodeHash: hash}}))
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "", "encrypted owner profile")
	cmd.Flags().StringVar(&artifact, "artifact", "contracts/out/KnockRegistry.sol/KnockRegistry.json", "Foundry artifact")
	os.Exit(command.Run(cmd))
}
