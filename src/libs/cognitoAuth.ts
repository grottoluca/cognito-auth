import AWSConfig from './awsConfig'
import jwkToPem from 'jwk-to-pem'
import axios from 'axios'
import jwt from 'jsonwebtoken'
import logger from './logger'
import { CognitoRefreshToken } from 'amazon-cognito-identity-js'
import { Error as JSONAPIError } from 'jsonapi-serializer'
import type {
    ApiResponse,
    DecodedToken,
    SignUpResponse,
    PemKeys,
    VerifyMiddleware,
    ExpressRequest,
    ExpressResponse,
    ExpressNext,
    CognitoTokens
} from '../types'

/** Token use constants */
const TOKEN_USE_ACCESS = 'access'
const TOKEN_USE_ID = 'id'

/** Maximum token age in seconds (1 hour) */
const MAX_TOKEN_AGE = 60 * 60

/** Allowed token use types */
const ALLOWED_TOKEN_USES = [TOKEN_USE_ACCESS, TOKEN_USE_ID] as const

/** AWS Config instance */
let awsConfig: AWSConfig

/**
 * Create a custom error in JSON:API format
 * @param code - HTTP status code
 * @param title - Error title
 * @param message - Error detail message
 * @returns JSON:API formatted error
 */
function customError(code: number, title: string, message: string): any {
    return new JSONAPIError({
        status: code.toString(),
        title: title,
        detail: message
    })
}

/**
 * Initialize AWS Cognito configuration
 * @param region - AWS region (e.g., 'us-east-1')
 * @param identityPoolId - Cognito Identity Pool ID
 * @param userPoolId - Cognito User Pool ID
 * @param clientId - Cognito User Pool Client ID
 */
function _initConfig(region: string, identityPoolId: string, userPoolId: string, clientId: string): void {
    awsConfig = new AWSConfig(region, identityPoolId, userPoolId, clientId)
}

/**
 * Get the middleware function that will verify incoming requests
 * Downloads JWKS keys and verifies JWT tokens
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Express next function
 * @returns Verification middleware
 */
function _getVerifyMiddleware(req: ExpressRequest, res: ExpressResponse, next: ExpressNext): void {
    // Fetch the JWKS data used to verify the signature of incoming JWT tokens
    const pemsDownloadProm = _init()
        .catch((err): { err: Error } => {
            // Failed to get the JWKS data - all subsequent auth requests will fail
            logger.error(err)
            return { err }
        })
    return _verifyMiddleWare(pemsDownloadProm, req, res, next)
}

/**
 * One-time initialization to download JWK keys and convert to PEM format
 * @returns Promise resolving to PEM-encoded public keys
 */
function _init(): Promise<PemKeys> {
    return new Promise((resolve, reject) => {
        const config = {
            method: 'GET' as const,
            url: `${awsConfig.getIssuer()}/.well-known/jwks.json`,
        }

        axios(config).then(response => {
            if (!response.data || !response.data.keys) {
                logger.debug(`JWKS data is not in expected format. Response was: ${JSON.stringify(response)}`)
                reject(new Error('Internal error occurred downloading JWKS data.'))
                return
            }
            const pems: PemKeys = {}
            for (let i = 0; i < response.data.keys.length; i++) {
                const key = response.data.keys[i]
                if (key && key.kid) {
                    pems[key.kid] = jwkToPem(key)
                }
            }
            logger.info(`Successfully downloaded ${response.data.keys.length} JWK key(s)`)
            resolve(pems)
        }).catch(err => {
            logger.debug(`Failed to download JWKS data. err: ${err}`)
            reject(new Error('Internal error occurred downloading JWKS data.'))
        })
    })
}

/**
 * Verify the Authorization header and call the next middleware handler if appropriate
 * @param pemsDownloadProm - Promise resolving to PEM keys
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Express next function
 */
function _verifyMiddleWare(
    pemsDownloadProm: Promise<PemKeys | { err: Error }>,
    req: ExpressRequest,
    res: ExpressResponse,
    next: ExpressNext
): void {
    pemsDownloadProm.then((pems) => {
        return _verifyProm(pems, req.get('Authorization'))
    })
        .then((decoded) => {
            // Caller is authorized - copy some useful attributes into the req object for later use
            logger.debug(`Valid JWT token. Decoded: ${JSON.stringify(decoded)}.`)
            req.user = {
                sub: decoded.sub ?? '',
                token_use: decoded.token_use as 'access' | 'id'
            }
            if (decoded.token_use === TOKEN_USE_ACCESS && req.user && decoded.scope) {
                // access token specific fields
                req.user.scope = decoded.scope.split(' ')
                req.user.username = decoded.username
                req.user.email = decoded.username
            }
            if (decoded.token_use === TOKEN_USE_ID && req.user) {
                // id token specific fields
                req.user.email = decoded.email
                req.user.username = decoded['cognito:username']
            }
            next()
        })
        .catch((err) => {
            res.status(401).send(err)
        })
}

/**
 * Verify the Authorization header and return a promise
 * @param pems - PEM-encoded public keys or error object
 * @param auth - Authorization header value
 * @returns Promise resolving to decoded JWT payload
 */
function _verifyProm(pems: PemKeys | { err: Error }, auth: string | undefined): Promise<jwt.JwtPayload> {
    return new Promise((resolve, reject) => {
        if ('err' in pems) {
            reject(new Error(String(pems.err)))
            return
        }

        // Check the format of the auth header string and break out the JWT token part
        if (!auth || auth.length < 10) {
            reject(customError(401, 'Invalid authorization', 'Invalid or missing Authorization header. Expected to be in the format \'Bearer <your_JWT_token>\'.'))
            return
        }
        const authPrefix = auth.substring(0, 7).toLowerCase()
        if (authPrefix !== 'bearer ') {
            reject(customError(401, 'Invalid authorization', 'Authorization header is expected to be in the format \'Bearer <your_JWT_token>\'.'))
            return
        }
        const token = auth.substring(7)

        // Decode the JWT token so we can match it to a key to verify it against
        const decodedNotVerified = jwt.decode(token, { complete: true })
        if (!decodedNotVerified || typeof decodedNotVerified === 'string') {
            logger.debug('Invalid JWT token. jwt.decode() failure.')
            reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.'))
            return
        }
        const kid = decodedNotVerified.header.kid
        if (!kid || !pems[kid]) {
            logger.debug(`Invalid JWT token. Expected a known KID ${JSON.stringify(Object.keys(pems))} but found ${kid}.`)
            reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.'))
            return
        }

        // Now verify the JWT signature matches the relevant key
        jwt.verify(token, pems[kid], {
            algorithms: ['RS256'],
            issuer: awsConfig.getIssuer(),
            maxAge: MAX_TOKEN_AGE
        },
        function (err: jwt.VerifyErrors | null, decodedAndVerified: string | jwt.JwtPayload | undefined) {
            if (err) {
                logger.debug(`Invalid JWT token. jwt.verify() failed: ${err}.`)
                if (err instanceof jwt.TokenExpiredError) {
                    reject(customError(401, 'Expired JWT token', `Authorization header contains a JWT token that expired at ${err.expiredAt.toISOString()}.`))
                } else {
                    reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.'))
                }
                return
            }

            if (!decodedAndVerified || typeof decodedAndVerified === 'string') {
                reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.'))
                return
            }

            // The signature matches so we know the JWT token came from our Cognito instance, now just verify the remaining claims in the token

            // Verify the token_use matches what we've been configured to allow
            if (ALLOWED_TOKEN_USES.indexOf(decodedAndVerified.token_use as typeof ALLOWED_TOKEN_USES[number]) === -1) {
                logger.debug(`Invalid JWT token. Expected token_use to be ${JSON.stringify(ALLOWED_TOKEN_USES)} but found ${decodedAndVerified.token_use}.`)
                reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.'))
                return
            }

            // Verify the client id matches what we expect. Will be in either the aud or the client_id claim depending on whether it's an id or access token.
            const clientId = (decodedAndVerified.aud || decodedAndVerified.client_id)
            if (clientId !== awsConfig.getClientId()) {
                logger.debug(`Invalid JWT token. Expected client id to be ${awsConfig.getClientId()} but found ${clientId}.`)
                reject(customError(401, 'Invalid token', 'Authorization header contains an invalid JWT token.'))
                return
            }

            // Done - all JWT token claims can now be trusted
            return resolve(decodedAndVerified)
        })
    })
}

/**
 * Sign in a user with email and password
 * @param email - User email address
 * @param password - User password
 * @returns Promise with authentication result
 */
function _signIn(email: string, password: string): Promise<ApiResponse<DecodedToken | any>> {
    return new Promise((resolve) => {
        awsConfig.getCognitoUser(email).authenticateUser(awsConfig.getAuthDetails(email, password), {
            onSuccess: (result) => {
                const token: CognitoTokens = {
                    accessToken: result.getAccessToken().getJwtToken(),
                    idToken: result.getIdToken().getJwtToken(),
                    refreshToken: result.getRefreshToken().getToken(),
                }
                return resolve({ statusCode: 200, response: awsConfig.decodeJWTToken(token) })
            },

            onFailure: (_err) => {
                return resolve({ statusCode: 401, response: customError(401, 'Unauthorized', 'Incorrect username or password.') })
            },
        })
    })
}

/**
 * Register a new user
 * @param email - User email address
 * @param password - User password
 * @param agent - User agent string (default: 'none')
 * @returns Promise with registration result
 */
function _signUp(email: string, password: string, agent = 'none'): Promise<ApiResponse<SignUpResponse | unknown>> {
    return new Promise((resolve) => {
        awsConfig.setCognitoAttributeList(email, agent)
        awsConfig.getUserPool().signUp(email, password, awsConfig.getCognitoAttributeList(), [], function (err, result) {
            if (err) {
                return resolve({ statusCode: 422, response: err })
            }
            if (!result) {
                return resolve({ statusCode: 422, response: new Error('Sign up failed') })
            }
            const response: SignUpResponse = {
                username: result.user.getUsername(),
                userConfirmed: result.userConfirmed,
                userAgent: (result.user as any).client?.userAgent || 'unknown',
                userSub: result.userSub
            }
            return resolve({ statusCode: 201, response: response })
        })
    })
}

/**
 * Change the password for the currently authenticated user
 * @param oldPassword - Current password
 * @param newPassword - New password
 * @returns Promise with password change result
 */
function _changePassword(oldPassword: string, newPassword: string): Promise<ApiResponse<string | unknown>> {
    return new Promise((resolve) => {
        const authUser = awsConfig.getUserPool().getCurrentUser()
        if (!authUser) {
            return resolve({ statusCode: 422, response: 'User is not authenticated' })
        }
        authUser.getSession((err: Error | null, _session: unknown) => {
            if (err) {
                return resolve({ statusCode: 422, response: err })
            }
            authUser.changePassword(oldPassword, newPassword, (err, result) => {
                if (err) {
                    return resolve({ statusCode: 422, response: err })
                }
                return resolve({ statusCode: 201, response: result })
            })
        })
    })
}

/**
 * Request a password reset code
 * @param email - User email address
 * @returns Promise with reset request result
 */
function _requestResetPassword(email: string): Promise<ApiResponse<string | unknown>> {
    return new Promise((resolve) => {
        const cognitoUser = awsConfig.getCognitoUser(email)
        if (!cognitoUser) {
            return resolve({ statusCode: 422, response: 'User not exist' })
        }

        cognitoUser.forgotPassword({
            onSuccess: (result) => {
                return resolve({ statusCode: 200, response: result })
            },

            onFailure: (err) => {
                return resolve({ statusCode: 422, response: err })
            }
        })
    })
}

/**
 * Reset password using confirmation code
 * @param email - User email address
 * @param confirmation_code - Confirmation code from email
 * @param newPassword - New password
 * @returns Promise with password reset result
 */
function _resetPassword(email: string, confirmation_code: string, newPassword: string): Promise<ApiResponse<string | unknown>> {
    return new Promise((resolve) => {
        const cognitoUser = awsConfig.getCognitoUser(email)
        if (!cognitoUser) {
            return resolve({ statusCode: 422, response: 'User not exist' })
        }

        cognitoUser.confirmPassword(confirmation_code, newPassword, {
            onSuccess: (result) => {
                return resolve({ statusCode: 201, response: result })
            },
            onFailure: (err) => {
                return resolve({ statusCode: 422, response: err })
            }
        })
    })
}

/**
 * Verify user email with confirmation code
 * @param email - User email address
 * @param code - Verification code from email
 * @returns Promise with verification result
 */
function _verify(email: string, code: string): Promise<ApiResponse<string | unknown>> {
    return new Promise((resolve) => {
        awsConfig.getCognitoUser(email).confirmRegistration(code, true, (err, result) => {
            if (err) {
                return resolve({ statusCode: 422, response: err })
            }
            return resolve({ statusCode: 200, response: result })
        })
    })
}

/**
 * Refresh authentication tokens
 * @param refreshToken - Refresh token
 * @param email - User email address
 * @returns Promise with refreshed tokens
 */
function _refresh(refreshToken: string, email: string): Promise<ApiResponse<DecodedToken | unknown>> {
    return new Promise((resolve) => {
        const token = new CognitoRefreshToken({ RefreshToken: refreshToken })
        awsConfig.getCognitoUser(email).refreshSession(token, function (err, result) {
            if (err) {
                return resolve({ statusCode: 422, response: err })
            }
            const newToken: CognitoTokens = {
                accessToken: result.getAccessToken().getJwtToken(),
                idToken: result.getIdToken().getJwtToken(),
                refreshToken: result.getRefreshToken().getToken(),
            }
            return resolve({ statusCode: 200, response: awsConfig.decodeJWTToken(newToken) })
        })
    })
}

/**
 * Sign out a user
 * @param email - User email address
 * @returns Promise with sign out result
 */
function _logOut(email: string): Promise<ApiResponse<unknown> | void> {
    return new Promise((resolve) => {
        awsConfig.getCognitoUser(email).signOut(() => {
            return resolve()
        })
    })
}

export const init = _initConfig
export const getVerifyMiddleware: VerifyMiddleware = _getVerifyMiddleware
export const signIn = _signIn
export const signUp = _signUp
export const logOut = _logOut
export const refresh = _refresh
export const verify = _verify
export const changePassword = _changePassword
export const requestResetPassword = _requestResetPassword
export const resetPassword = _resetPassword
