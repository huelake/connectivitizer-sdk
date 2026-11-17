import { PlatformApi } from './api.js';
import { ConnectivitizerError, ErrorCodes } from './errors.js';
import type { Platform } from './platform.js';
import { delay } from './streams.js';

// Linking an app to somebody's account without a login inside the app (protocol section 11.5).

export interface LinkPrompt {
  /** The page of the web app to send the person to, with the code already filled in. */
  url: string;
  /** The same page without the code, for showing it next to the code. */
  page: string;
  /** The short code the page must show, e.g. `KQTR-7MPL`. */
  code: string;
  /** Seconds the person has to approve. */
  expiresIn: number;
}

export interface LinkOptions {
  /** Base URL of the Connectivitizer API. */
  apiUrl: string;

  /** The name the app appears under in the workspace, e.g. `Lamp app`. */
  client: string;

  /** What the app runs on, e.g. `android`. Shown to the person who approves. */
  platformName?: string;

  /**
   * Ask to manage the workspace as well: keys, devices, who may reach what. For tools, not for
   * apps: only an admin can approve it, and the key expires after some weeks.
   */
  manage?: boolean;

  /**
   * Sends the person to the web app: open `url` in a browser, or show it as a link or QR code
   * together with `code`. Linking continues in the background while they are there.
   */
  onPrompt: (prompt: LinkPrompt) => void | Promise<void>;

  /** Stops waiting when it becomes aborted, for example because the user pressed "cancel". An `AbortSignal` fits. */
  signal?: { readonly aborted: boolean };
}

/** What a linked app holds from then on. The API key exists only here: store it where only the app can read it. */
export interface LinkedApp {
  apiKey: string;
  workspaceId: string;
  workspaceName: string;
  /** The name the app got in the workspace: the one it asked for, made distinct if it was taken. */
  client: string;
  credentialId: string;
  /** Whether the key may manage the workspace. */
  manage: boolean;
  /** When the key stops working, if it does (ISO 8601). */
  expiresAt?: string;
}

/**
 * Links this app to an account: the person signs in to the web app in a browser and approves,
 * and the app receives an API key of its own. The app never sees the person's sign-in, and no
 * redirect back into the app is needed - the app simply asks until the answer is there.
 *
 * Rejects with `LINK_DENIED` when the person refused, and with `LINK_EXPIRED` when nobody
 * decided in time or the wait was cancelled.
 */
export async function linkWith(platform: Pick<Platform, 'fetch'>, options: LinkOptions): Promise<LinkedApp> {
  const api = new PlatformApi(options.apiUrl, platform as Platform);
  const link = await api.startLink(options.client, options.platformName, options.manage);
  await options.onPrompt({ url: link.verificationUrlComplete, page: link.verificationUrl, code: link.userCode, expiresIn: link.expiresIn });

  const deadline = Date.now() + link.expiresIn * 1000;
  const interval = Math.min(Math.max(link.interval, 1), 30) * 1000;
  while (Date.now() < deadline) {
    await delay(interval);
    if (options.signal?.aborted) {
      throw new ConnectivitizerError(ErrorCodes.LinkExpired, 'Linking was cancelled.');
    }
    const answer = await api.pollLink(link.deviceCode);
    if (answer.status === 'approved' && answer.apiKey) {
      return {
        apiKey: answer.apiKey,
        workspaceId: answer.workspaceId ?? '',
        workspaceName: answer.workspaceName ?? '',
        client: answer.client ?? options.client,
        credentialId: answer.credentialId ?? '',
        manage: answer.manage === true,
        expiresAt: answer.expiresAt ?? undefined,
      };
    }
  }
  throw new ConnectivitizerError(ErrorCodes.LinkExpired, 'Nobody approved the link in time.');
}
