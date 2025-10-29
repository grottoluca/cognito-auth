const { CognitoIdentityClient } = require('@aws-sdk/client-cognito-identity')
const { fromCognitoIdentityPool } = require('@aws-sdk/credential-providers')
const jwt = require('jsonwebtoken')
const AmazonCognitoIdentity = require('amazon-cognito-identity-js')
let cognitoAttributeList = []

class AWSConfig {

    constructor (region, identityPoolId, userPoolId, clientId) {
        // Store region for future use
        this.region = region

        // Create Cognito Identity client for AWS SDK v3
        this.cognitoIdentityClient = new CognitoIdentityClient({ region })

        // Create credentials provider using AWS SDK v3
        // This replaces AWS.config.credentials from v2
        this.credentials = fromCognitoIdentityPool({
            client: this.cognitoIdentityClient,
            identityPoolId: identityPoolId
        })

        this.poolData = {
            UserPoolId: userPoolId,
            ClientId: clientId,
        }
        this.issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`
    }

    attributes(key, value) { 
        return {
            Name: key,
            Value: value
        }
    }
  
    setCognitoAttributeList(email, agent) {
        let attributeList = []
        attributeList.push(this.attributes('email',email))
        attributeList.forEach(element => {
            cognitoAttributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute(element))
        })
    }
  
    getCognitoAttributeList() {
        return cognitoAttributeList
    }
  
    getCognitoUser(email) {
        const userData = {
            Username: email,
            Pool: this.getUserPool()
        }
        return new AmazonCognitoIdentity.CognitoUser(userData)
    }

    getUserPool(){
        return new AmazonCognitoIdentity.CognitoUserPool(this.poolData)
    }

    getAuthDetails(email, password) {
        let authenticationData = {
            Username: email,
            Password: password,
        }
        return new AmazonCognitoIdentity.AuthenticationDetails(authenticationData)
    }

    getIssuer() {
        return this.issuer
    }

    getClientId() {
        return this.poolData.ClientId
    }

    decodeJWTToken(token) {
        const {  email, exp, auth_time , token_use, sub} = jwt.decode(token.idToken)
        return {  token, email, exp, uid: sub, auth_time, token_use }
    }
}
module.exports = AWSConfig
