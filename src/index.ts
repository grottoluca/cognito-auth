/**
 * AWS Cognito Authentication Library
 *
 * TypeScript-based authentication library for AWS Cognito User Pools
 * with full backward compatibility for existing JavaScript projects.
 *
 * @packageDocumentation
 */

import {
    init,
    getVerifyMiddleware,
    signUp,
    signIn,
    logOut,
    refresh,
    verify,
    changePassword,
    requestResetPassword,
    resetPassword
} from './libs/cognitoAuth'

// Export all functions
export {
    init,
    getVerifyMiddleware,
    signUp,
    signIn,
    logOut,
    refresh,
    verify,
    changePassword,
    requestResetPassword,
    resetPassword
}

// Export all types for TypeScript consumers
export type {
    CognitoTokens,
    DecodedToken,
    ApiResponse,
    SignUpResponse,
    AuthenticatedUser,
    VerifyMiddleware,
    ExpressRequest,
    ExpressResponse,
    ExpressNext,
    PemKeys,
    CognitoConfig,
    PoolData
} from './types'
