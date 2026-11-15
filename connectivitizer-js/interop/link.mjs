// An app that links itself to an account, for the interoperability tests.
//
//   CZ_API_URL, CZ_CLIENT (default "Node app")
//
// It prints "PROMPT <json>" when the person has to approve in the web app, and at the end
// "LINKED <json>" with the API key it received, or "FAILED <code>".

import { ConnectivitizerError, linkApp } from '../dist/index.js';

try {
  const linked = await linkApp({
    apiUrl: process.env.CZ_API_URL,
    client: process.env.CZ_CLIENT ?? 'Node app',
    onPrompt: (prompt) => console.log('PROMPT ' + JSON.stringify(prompt)),
  });
  console.log('LINKED ' + JSON.stringify(linked));
} catch (error) {
  console.log('FAILED ' + (error instanceof ConnectivitizerError ? error.code : String(error?.message ?? error)));
  process.exitCode = 2;
}
