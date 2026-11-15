#!/usr/bin/env node
import { newSharedKey } from './index.js';

const [command] = process.argv.slice(2);
if (command === 'keygen') {
  // The key is made here and printed once. It is never sent anywhere.
  console.log(newSharedKey());
} else {
  console.log(`connectivitizer - helper of the Connectivitizer SDK

  connectivitizer keygen    print a new shared key (czs_...) to put on both endpoints`);
  process.exitCode = command === undefined || command === 'help' || command === '--help' ? 0 : 64;
}
