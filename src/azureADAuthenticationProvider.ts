import { authentication, AuthenticationProvider, AuthenticationProviderAuthenticationSessionsChangeEvent, AuthenticationSession, Disposable, env, EventEmitter, ExtensionContext, ProgressLocation, Uri, UriHandler, window } from "vscode";
import { v4 as uuid } from 'uuid';
import fetch from 'node-fetch';
import { PromiseAdapter, promiseFromEvent } from "./util";

export const AUTH_TYPE = `azuread`;
const AUTH_NAME = `Azure AD`;
const CLIENT_ID = `f3164c21-b4ca-416c-915c-299458eba95b`;
const REDIRECT_URI = `eliostruyf.vscode-azuread-authprovider`;
const MICROSOFT_LOGIN_URI = `https://login.microsoftonline.com/common/oauth2/v2.0`;
const SESSIONS_SECRET_KEY = `${AUTH_TYPE}.sessions`

class UriEventHandler extends EventEmitter<Uri> implements UriHandler {
	public handleUri(uri: Uri) {
		this.fire(uri);
	}
}

export class AzureADAuthenticationProvider implements AuthenticationProvider, Disposable {
	private _sessionChangeEmitter = new EventEmitter<AuthenticationProviderAuthenticationSessionsChangeEvent>();
	private _disposable: Disposable;
  private _pendingNonces: string[] = [];
  private _codeExchangePromises = new Map<string, { promise: Promise<string>; cancel: EventEmitter<void> }>();
  private _uriHandler = new UriEventHandler();

  constructor(private readonly context: ExtensionContext) {
    this._disposable = Disposable.from(
      authentication.registerAuthenticationProvider(AUTH_TYPE, AUTH_NAME, this, { supportsMultipleAccounts: false }),
      window.registerUriHandler(this._uriHandler)
    )
  }

	get onDidChangeSessions() {
		return this._sessionChangeEmitter.event;
	}

  get redirectUri() {
    return `${env.uriScheme}://${REDIRECT_URI}`;
  }

  /**
   * Get the existing sessions
   * @param scopes 
   * @returns 
   */
  public async getSessions(scopes?: readonly string[]): Promise<readonly AuthenticationSession[]> {
    const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY);

    if (allSessions) {
      return JSON.parse(allSessions) as AuthenticationSession[];
    }

    return [];
  }

  /**
   * Create a new auth session
   * @param scopes 
   * @returns 
   */
  public async createSession(scopes: readonly string[]): Promise<AuthenticationSession> {
    try {
      const token = await this.login();
      if (!token) {
        throw new Error(`Azure AD login failure`);
      }

      const session = await this.tokenToSession(token, scopes);

      await this.context.secrets.store(SESSIONS_SECRET_KEY, JSON.stringify([session]))
      
      this._sessionChangeEmitter.fire({ added: [session], removed: [], changed: [] });

      return session;
    } catch (e) {
      window.showErrorMessage(`Sign in failed: ${e}`);
			throw e;
    }
  }

  /**
   * Remove an existing session
   * @param sessionId 
   */
  public async removeSession(sessionId: string): Promise<void> {
    const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY);
    if (allSessions) {
      let sessions = JSON.parse(allSessions) as AuthenticationSession[];
      const sessionIdx = sessions.findIndex(s => s.id === sessionId);
      const session = sessions[sessionIdx];
      sessions.splice(sessionIdx, 1);

      await this.context.secrets.store(SESSIONS_SECRET_KEY, JSON.stringify(sessions));

      if (session) {
        this._sessionChangeEmitter.fire({ added: [], removed: [session], changed: [] });
      }      
    }
  }

  /**
   * Dispose the registered services
   */
	public async dispose() {
		this._disposable.dispose();
	}

  /**
   * Start the Azure AD login
   * @returns 
   */
  private async login(): Promise<string | undefined> {
    return await window.withProgress<string>({
			location: ProgressLocation.Notification,
			title: "Signing in to Azure AD...",
			cancellable: true
		}, async (_, token) => {
      const nonce = uuid();

      this._pendingNonces.push(nonce);

      const scopes = ["https://graph.microsoft.com/User.Read"];
      const scopeString = scopes.join(' ');

      const searchParams = new URLSearchParams([
        ['client_id', CLIENT_ID],
        ['redirect_uri', this.redirectUri],
        ['state', nonce],
        ['scope', scopeString],
        ['response_type', "code"],
        ['response_mode', "query"],
        ['prompt', "consent"]
      ]);
      const uri = Uri.parse(`${MICROSOFT_LOGIN_URI}/authorize?${searchParams.toString()}`);
      await env.openExternal(uri);

      let codeExchangePromise = this._codeExchangePromises.get(scopeString);
      if (!codeExchangePromise) {
        codeExchangePromise = promiseFromEvent(this._uriHandler.event, this.handleUri(scopes));
        this._codeExchangePromises.set(scopeString, codeExchangePromise);
      }

      try {
        return await Promise.race([
          codeExchangePromise.promise,
          new Promise<string>((_, reject) => setTimeout(() => reject('Cancelled'), 60000)),
          promiseFromEvent<any, any>(token.onCancellationRequested, (_, __, reject) => { reject('User Cancelled'); }).promise
        ]);
      } finally {
        this._pendingNonces = this._pendingNonces.filter(n => n !== nonce);
        codeExchangePromise?.cancel.fire();
        this._codeExchangePromises.delete(scopeString);
      }
    });
  }

  /**
   * Create an Authentication Session for the token
   * @param token 
   * @param scopes 
   * @returns 
   */
  private async tokenToSession(token: string, scopes: readonly string[]): Promise<AuthenticationSession> {
    if(token !== null || token !== undefined){
      const base64String = token.split(".")[1];
      const decodedValue = JSON.parse(Buffer.from(base64String, "base64").toString("ascii"));
      
      return {
        id: uuid(),
        accessToken: token,
        account: { label: decodedValue.name, id: decodedValue.upn },
        scopes
      };
    }

    throw new Error(`Not a valid token`);
	}

  /**
   * Handle the redirect to VS Code (after sign in)
   * @param scopes 
   * @returns 
   */
  private handleUri: (scopes: readonly string[]) => PromiseAdapter<Uri, string> = 
  (scopes) => async (uri, resolve, reject) => {
    const query = new URLSearchParams(uri.query);
    const code = query.get('code');
    const state = query.get('state');
    if (!code) {
      reject(new Error('No code'));
      return;
    }
    if (!state) {
      reject(new Error('No state'));
      return;
    }

    // Check if it is a valid auth request started by the extension
    if (!this._pendingNonces.some(n => n === state)) {
      return;
    }

    const body = `client_id=${CLIENT_ID}&code=${code}&grant_type=authorization_code&redirect_uri=${this.redirectUri}&scope=${scopes.join(` `)}&state=${state}`;
		const result = await fetch(`${MICROSOFT_LOGIN_URI}/token`, {
			method: 'POST',
			headers: {
				Accept: 'application/json',
				'Content-Type': 'application/x-www-form-urlencoded',
				'Content-Length': body.toString()
			},
			body
		});

    if (result.ok) {
			const json = await result.json();
			resolve(json.access_token);
		} else {
			const text = await result.text();
			const error = new Error(text);
			error.name = 'GitHubTokenExchangeError';
			throw error;
		}
  }
}