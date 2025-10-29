import { CognitoUser, CognitoUserPool, CognitoUserAttribute, AuthenticationDetails } from 'amazon-cognito-identity-js'

/**
 * Generic Express-like request object
 */
export interface ExpressRequest {
    /** Get header value by name */
    get(name: string): string | undefined
    /** User data (added by middleware) */
    user?: AuthenticatedUser
    [key: string]: unknown
}

/**
 * Generic Express-like response object
 */
export interface ExpressResponse {
    /** Send response with status code */
    status(code: number): {
        send(data: unknown): void
    }
    [key: string]: unknown
}

/**
 * Generic Express-like next function
 */
export type ExpressNext = () => void

/**
 * Cognito authentication tokens returned after successful authentication
 */
export interface CognitoTokens {
    /** JWT access token for API authentication */
    accessToken: string
    /** JWT ID token containing user claims */
    idToken: string
    /** Refresh token for obtaining new access/ID tokens */
    refreshToken: string
}

/**
 * Decoded JWT token with user information
 */
export interface DecodedToken {
    /** Cognito tokens */
    token: CognitoTokens
    /** User email address */
    email: string
    /** Token expiration timestamp */
    exp: number
    /** User unique identifier */
    uid: string
    /** Authentication timestamp */
    auth_time: number
    /** Token use type (id or access) */
    token_use: string
}

/**
 * Standard API response format
 */
export interface ApiResponse<T = unknown> {
    /** HTTP status code */
    statusCode: number
    /** Response data */
    response: T
}

/**
 * Sign-up response data
 */
export interface SignUpResponse {
    /** Username of the registered user */
    username: string
    /** Whether the user is confirmed */
    userConfirmed: boolean
    /** User agent used during registration */
    userAgent: string
    /** User subscription ID */
    userSub: string
}

/**
 * User information attached to Express request after authentication
 */
export interface AuthenticatedUser {
    /** User subject (unique identifier) */
    sub: string
    /** Token use type */
    token_use: 'access' | 'id'
    /** User email address */
    email?: string
    /** Username from Cognito */
    username?: string
    /** Access token scopes (only for access tokens) */
    scope?: string[]
}

/**
 * Express middleware function type for JWT verification
 */
export type VerifyMiddleware = (
    req: ExpressRequest,
    res: ExpressResponse,
    next: ExpressNext
) => void

/**
 * PEM-encoded public keys indexed by key ID
 */
export interface PemKeys {
    [kid: string]: string
}

/**
 * AWS Cognito configuration parameters
 */
export interface CognitoConfig {
    /** AWS region (e.g., 'us-east-1') */
    region: string
    /** Cognito Identity Pool ID */
    identityPoolId: string
    /** Cognito User Pool ID */
    userPoolId: string
    /** Cognito User Pool Client ID */
    clientId: string
}

/**
 * User pool data for Cognito operations
 */
export interface PoolData {
    /** Cognito User Pool ID */
    UserPoolId: string
    /** Cognito User Pool Client ID */
    ClientId: string
}

// Re-export commonly used types from dependencies
export type { CognitoUser, CognitoUserPool, CognitoUserAttribute, AuthenticationDetails }
