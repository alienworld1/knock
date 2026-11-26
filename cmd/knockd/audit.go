package main

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"

	"knock/internal/admission"
	"knock/internal/command"
	"knock/internal/door"
	"knock/internal/protocol"
)

func auditExportCommand(configPath *string) *cobra.Command {
	var recipient string
	cmd := &cobra.Command{
		Use: "audit-export <receipt-id>", Short: "Export an encrypted receipt from a stopped Door", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var id common.Hash
			if id.UnmarshalText([]byte(args[0])) != nil || id == (common.Hash{}) {
				return command.Exit(2, errors.New("set a nonzero 32-byte receipt reference in hex"))
			}
			if _, err := door.ParseAccount(recipient); err != nil {
				return command.Exit(2, errors.New("set the auditor account with --recipient"))
			}
			config, err := door.LoadConfig(*configPath)
			if err != nil {
				return command.Exit(2, err)
			}
			if !config.Audit {
				return command.Exit(2, errors.New("audit history is disabled for the Door"))
			}
			db, err := protocol.OpenState(config.State)
			if err != nil {
				return command.Exit(8, errors.New("couldn't open the audit archive. Check the state file and stop the Door before exporting."))
			}
			defer db.Close()
			data, err := admission.ExportAuditReceipt(db, id, recipient)
			if err != nil {
				return command.Exit(8, err)
			}
			_, err = cmd.OutOrStdout().Write(data)
			return command.Exit(8, err)
		},
	}
	cmd.Flags().StringVar(&recipient, "recipient", "", "auditor account belonging to the receipt epoch")
	return cmd
}
