# Sample 1

```typescript
import { authentication, AuthenticationProvider, AuthenticationProviderAuthenticationSessionsChangeEvent, AuthenticationSession, Disposable, EventEmitter, ExtensionContext } from "vscode";

export const AUTH_TYPE = `auth0`;
const AUTH_NAME = `Auth0`;

export class Auth0AuthenticationProvider implements AuthenticationProvider, Disposable {
	private _sessionChangeEmitter = new EventEmitter<AuthenticationProviderAuthenticationSessionsChangeEvent>();
  private _disposable: Disposable;
  
  constructor(private readonly context: ExtensionContext) {
    this._disposable = Disposable.from(
      authentication.registerAuthenticationProvider(AUTH_TYPE, AUTH_NAME, this, { supportsMultipleAccounts: false })
    )
  }

  get onDidChangeSessions() {
    return this._sessionChangeEmitter.event;
  }

  /**
   * Get the existing sessions
   * @param scopes 
   * @returns 
   */
  public async getSessions(scopes?: string[]): Promise<readonly AuthenticationSession[]> {
    return [];
  }

  /**
   * Create a new auth session
   * @param scopes 
   * @returns 
   */
  public async createSession(scopes: string[]): Promise<AuthenticationSession> {
    return null as any as AuthenticationSession;
  }

  /**
   * Remove an existing session
   * @param sessionId 
   */
  public async removeSession(sessionId: string): Promise<void> {
    
  }

  /**
   * Dispose the registered services
   */
	public async dispose() {
		this._disposable.dispose();
	}
}
```


## Sample 2

```typescript
const AUTH_TYPE = `auth0`;
const AUTH_NAME = `Auth0`;
const SESSIONS_SECRET_KEY = `${AUTH_TYPE}.sessions`

export class Auth0AuthenticationProvider implements AuthenticationProvider, Disposable {
  
  // Shortened for brevity

  public async createSession(scopes: string[]): Promise<AuthenticationSession> {
    try {
      const token = await this.login(scopes);
      if (!token) {
        throw new Error(`Auth0 login failure`);
      }

      const userinfo: { name: string, email: string } = await this.getUserInfo(token);

      const session: AuthenticationSession = {
        id: uuid(),
        accessToken: token,
        account: {
          label: userinfo.name,
          id: userinfo.email
        },
        scopes: []
      };

      await this.context.secrets.store(SESSIONS_SECRET_KEY, JSON.stringify([session]))

      this._sessionChangeEmitter.fire({ added: [session], removed: [], changed: [] });

      return session;
    } catch (e) {
      window.showErrorMessage(`Sign in failed: ${e}`);
      throw e;
    }
  }
}
```


## Sample 3

```typescript
const AUTH_TYPE = `auth0`;
const AUTH_NAME = `Auth0`;
const CLIENT_ID = `3GUryQ7ldAeKEuD2obYnppsnmj58eP5u`;
const AUTH0_DOMAIN = `dev-txghew0y.us.auth0.com`;
const SESSIONS_SECRET_KEY = `${AUTH_TYPE}.sessions`

export class Auth0AuthenticationProvider implements AuthenticationProvider, Disposable {
  
  // Shortened for brevity

  private async login(scopes: string[] = []) {
    return await window.withProgress<string>({
			location: ProgressLocation.Notification,
			title: "Signing in to Auth0...",
			cancellable: true
		}, async (_, token) => {
      const stateId = uuid();

      this._pendingStates.push(stateId);

      if (!scopes.includes('openid')) {
        scopes.push('openid');
      }
      if (!scopes.includes('profile')) {
        scopes.push('profile');
      }
      if (!scopes.includes('email')) {
        scopes.push('email');
      }

      const scopeString = scopes.join(' ');

      const searchParams = new URLSearchParams([
        ['response_type', "token"],
        ['client_id', CLIENT_ID],
        ['redirect_uri', this.redirectUri],
        ['state', stateId],
        ['scope', scopeString],
        ['prompt', "login"]
      ]);
      const uri = Uri.parse(`https://${AUTH0_DOMAIN}/authorize?${searchParams.toString()}`);
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
        this._pendingStates = this._pendingStates.filter(n => n !== stateId);
        codeExchangePromise?.cancel.fire();
        this._codeExchangePromises.delete(scopeString);
      }
    });
  }
}
```

## Sample 4

```typescript
class UriEventHandler extends EventEmitter<Uri> implements UriHandler {
	public handleUri(uri: Uri) {
		this.fire(uri);
	}
}

export class Auth0AuthenticationProvider implements AuthenticationProvider, Disposable {
  
  constructor(private readonly context: ExtensionContext) {
    this._disposable = Disposable.from(
      authentication.registerAuthenticationProvider(AUTH_TYPE, AUTH_NAME, this, { supportsMultipleAccounts: false }),
      window.registerUriHandler(this._uriHandler) // Register the URI handler
    )
  }

  // Shortened for brevity

   /**
   * Handle the redirect to VS Code (after sign in from Auth0)
   * @param scopes 
   * @returns 
   */
  private handleUri: (scopes: readonly string[]) => PromiseAdapter<Uri, string> = 
  (scopes) => async (uri, resolve, reject) => {
    const query = new URLSearchParams(uri.fragment);
    const access_token = query.get('access_token');
    const state = query.get('state');

    if (!access_token) {
      reject(new Error('No token'));
      return;
    }
    if (!state) {
      reject(new Error('No state'));
      return;
    }

    // Check if it is a valid auth request started by the extension
    if (!this._pendingStates.some(n => n === state)) {
      reject(new Error('State not found'));
      return;
    }

    resolve(access_token);
  }
}
```


```typescript
const AUTH_TYPE = `auth0`;
const SESSIONS_SECRET_KEY = `${AUTH_TYPE}.sessions`

export class Auth0AuthenticationProvider implements AuthenticationProvider, Disposable {
  
  // Shortened for brevity


  /**
   * Get the existing sessions
   * @param scopes 
   * @returns 
   */
  public async getSessions(scopes?: string[]): Promise<readonly AuthenticationSession[]> {
    const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY);

    if (allSessions) {
      return JSON.parse(allSessions) as AuthenticationSession[];
    }

    return [];
  }
}
```


```typescript
const AUTH_TYPE = `auth0`;
const SESSIONS_SECRET_KEY = `${AUTH_TYPE}.sessions`

export class Auth0AuthenticationProvider implements AuthenticationProvider, Disposable {
  
  // Shortened for brevity

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
}
```