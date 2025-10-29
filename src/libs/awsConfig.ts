import { CognitoIdentityClient } from '@aws-sdk/client-cognito-identity'
import { fromCognitoIdentityPool } from '@aws-sdk/credential-providers'
import jwt from 'jsonwebtoken'
import {
    CognitoUser,
    CognitoUserPool,
    CognitoUserAttribute,
    AuthenticationDetails,
    ICognitoUserAttributeData
} from 'amazon-cognito-identity-js'
import type { PoolData, CognitoTokens, DecodedToken } from '../types'

/** Cached list of Cognito user attributes */
let cognitoAttributeList: CognitoUserAttribute[] = []

/**
 * AWS Cognito configuration and utility class
 * Manages AWS SDK v3 clients and Cognito User Pool operations
 */
class AWSConfig {
    /** AWS region */
    readonly region: string

    /** Cognito Identity client for AWS SDK v3 */
    readonly cognitoIdentityClient: CognitoIdentityClient

    /** Credentials provider using AWS SDK v3 */
    readonly credentials: ReturnType<typeof fromCognitoIdentityPool>

    /** User Pool configuration data */
    private readonly poolData: PoolData

    /** Cognito issuer URL for JWT verification */
    private readonly issuer: string

    /**
     * Initialize AWS Cognito configuration
     * @param region - AWS region (e.g., 'us-east-1')
     * @param identityPoolId - Cognito Identity Pool ID
     * @param userPoolId - Cognito User Pool ID
     * @param clientId - Cognito User Pool Client ID
     */
    constructor(region: string, identityPoolId: string, userPoolId: string, clientId: string) {
        this.region = region

        // Create Cognito Identity client for AWS SDK v3
        this.cognitoIdentityClient = new CognitoIdentityClient({ region })

        // Create credentials provider using AWS SDK v3
        // This replaces AWS.config.credentials from v2
        this.credentials = fromCognitoIdentityPool({
            identityPoolId: identityPoolId,
            clientConfig: { region }
        })

        this.poolData = {
            UserPoolId: userPoolId,
            ClientId: clientId,
        }
        this.issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`
    }

    /**
     * Create a Cognito user attribute object
     * @param key - Attribute name
     * @param value - Attribute value
     * @returns Cognito user attribute data
     */
    attributes(key: string, value: string): ICognitoUserAttributeData {
        return {
            Name: key,
            Value: value
        }
    }

    /**
     * Build and cache Cognito attribute list for user registration
     * @param email - User email address
     * @param _agent - User agent string (currently unused)
     */
    setCognitoAttributeList(email: string, _agent: string): void {
        const attributeList: ICognitoUserAttributeData[] = []
        attributeList.push(this.attributes('email', email))
        attributeList.forEach(element => {
            cognitoAttributeList.push(new CognitoUserAttribute(element))
        })
    }

    /**
     * Get the cached Cognito attribute list
     * @returns Array of Cognito user attributes
     */
    getCognitoAttributeList(): CognitoUserAttribute[] {
        return cognitoAttributeList
    }

    /**
     * Create a Cognito user object
     * @param email - User email (used as username)
     * @returns Cognito user instance
     */
    getCognitoUser(email: string): CognitoUser {
        const userData = {
            Username: email,
            Pool: this.getUserPool()
        }
        return new CognitoUser(userData)
    }

    /**
     * Get the Cognito User Pool instance
     * @returns Cognito User Pool
     */
    getUserPool(): CognitoUserPool {
        return new CognitoUserPool(this.poolData)
    }

    /**
     * Create authentication details for sign-in
     * @param email - User email
     * @param password - User password
     * @returns Authentication details object
     */
    getAuthDetails(email: string, password: string): AuthenticationDetails {
        const authenticationData = {
            Username: email,
            Password: password,
        }
        return new AuthenticationDetails(authenticationData)
    }

    /**
     * Get the Cognito issuer URL
     * @returns Issuer URL for JWT verification
     */
    getIssuer(): string {
        return this.issuer
    }

    /**
     * Get the Cognito User Pool Client ID
     * @returns Client ID
     */
    getClientId(): string {
        return this.poolData.ClientId
    }

    /**
     * Decode JWT token and extract user information
     * @param token - Cognito authentication tokens
     * @returns Decoded token with user data
     */
    decodeJWTToken(token: CognitoTokens): DecodedToken {
        const decoded = jwt.decode(token.idToken) as {
            email: string
            exp: number
            auth_time: number
            token_use: string
            sub: string
        }
        const { email, exp, auth_time, token_use, sub } = decoded
        return { token, email, exp, uid: sub, auth_time, token_use }
    }
}

export default AWSConfig
