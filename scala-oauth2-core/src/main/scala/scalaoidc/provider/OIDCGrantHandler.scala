package scalaoidc.provider

import scalaoauth2.provider._
import com.nimbusds.openid.connect.sdk.{AuthenticationSuccessResponse, AuthenticationRequest}
import com.nimbusds.oauth2.sdk.AuthorizationCode

case class OIDCGrantHandlerResult(tokenType: String, accessToken: String, expiresIn: Option[Long], refreshToken: Option[String], scope: Option[String], idToken: String) extends GrantHandlerResult

trait OIDCGrantHandler {
  def handleRequest[U](request: AuthenticationRequest, dataHandler: OIDCDataHandler[U]): AuthenticationSuccessResponse
}

class OIDCAuthCodeFlow extends OIDCGrantHandler {

  override def handleRequest[U](request: AuthenticationRequest, dataHandler: OIDCDataHandler[U]): AuthenticationSuccessResponse = {

    val clientId = request.getClientID
    val scope = request.getScope
    val redirectUri = request.getRedirectionURI
    val user = dataHandler.findUser(request.toParameters.get("username"), request.toParameters.get("password")).getOrElse(throw new InvalidRequest())
    val authInfo = AuthInfo(user, clientId.getValue, Some(scope.toString), Some(redirectUri.toString))
    val authCode = dataHandler.getStoredAuthCode(authInfo) match {
      case Some(code) => code
      case None => dataHandler.createAuthCode(authInfo)
    }

    new AuthenticationSuccessResponse(request.getRedirectionURI, new AuthorizationCode(authCode.authorizationCode), null, null, request.getState)
  }
}

class OIDCImplicitFlow extends OIDCGrantHandler {

  override def handleRequest[U](request: AuthenticationRequest, dataHandler: OIDCDataHandler[U]): AuthenticationSuccessResponse = {
    val clientId = request.getClientID
    val scope = request.getScope
    val redirectUri = request.getRedirectionURI
    val user = dataHandler.findUser(request.toParameters.get("username"), request.toParameters.get("password")).getOrElse(throw new InvalidRequest())
    val authInfo = AuthInfo(user, clientId.getValue, Some(scope.toString), Some(redirectUri.toString))

    new AuthenticationSuccessResponse(request.getRedirectionURI, null, dataHandler.createIDToken(authInfo, None), null, request.getState)
  }
}

class OIDCTokenRequest(clientCredentialFetcher: ClientCredentialFetcher) extends GrantHandler {

  override def handleRequest[U](request: AuthorizationRequest, dataHandler: DataHandler[U]): GrantHandlerResult = {
    val clientCredential = clientCredentialFetcher.fetch(request).getOrElse(throw new InvalidRequest("BadRequest"))
    val clientId = clientCredential.clientId
    val redirectUri = request.redirectUri
    val authInfo = dataHandler.findAuthInfoByCode(request.requireCode).getOrElse(throw new InvalidGrant())
    if (authInfo.clientId != clientId) {
      throw new InvalidClient
    }

    if (authInfo.redirectUri != redirectUri) {
      throw new RedirectUriMismatch
    }

    issueAccessToken(dataHandler, authInfo)
  }

  /**
   * Returns valid access token.
   *
   * @param dataHandler
   * @param authInfo
   * @return
   */
  def issueAccessToken[U](dataHandler: OIDCDataHandler[U], authInfo: AuthInfo[U]): GrantHandlerResult = {
    val accessToken = dataHandler.getStoredAccessToken(authInfo) match {
      case Some(token) if dataHandler.isAccessTokenExpired(token) =>
        token.refreshToken.map(dataHandler.refreshAccessToken(authInfo, _)).getOrElse(dataHandler.createAccessToken(authInfo))
      case Some(token) => token
      case None => dataHandler.createAccessToken(authInfo)
    }

    val idToken = dataHandler.createIDToken(authInfo, Some(accessToken))

    OIDCGrantHandlerResult(
      "Bearer",
      accessToken.token,
      accessToken.expiresIn,
      accessToken.refreshToken,
      None,
      idToken.serialize
    )
  }

}
