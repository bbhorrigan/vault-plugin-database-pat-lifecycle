// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	snowflakepat "github.com/bbhorrigan/vault-plugin-secrets-snowflakepat"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatalf("failed to parse flags: %s", err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: snowflakepat.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatalf("plugin serve error: %s", err)
	}
}
