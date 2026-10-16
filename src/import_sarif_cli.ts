#!/usr/bin/env node
import { runImportSarifCli } from "./sarif_import.ts";

process.exitCode = await runImportSarifCli(process.argv.slice(2));
