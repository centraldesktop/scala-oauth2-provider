package scalaoidc.provider

import scalaoauth2.provider._
import com.nimbusds.openid.connect.sdk.{AuthenticationSuccessResponse, AuthenticationRequest}
import com.nimbusds.oauth2.sdk.AuthorizationCode

case class OIDCGrantHandlerResult(tokenType: String, accessToken: String, expiresIn: Option[Long], refreshToken: Option[String], scope: Option[String], idToken: String) extends GrantHandlerResult

trait OIDCGrantHandler {
  def handleRequest[U](request: AuthenticationRequest, dataHandler: OIDCDataHandler[U], user: U): AuthenticationSuccessResponse
}

class OIDCAuthCodeFlow extends OIDCGrantHandler {

  override def handleRequest[U](request: AuthenticationRequest, dataHandler: OIDCDataHandler[U], user: U): AuthenticationSuccessResponse = {

    val clientId = request.getClientID
    val scope = request.getScope
    val redirectUri = request.getRedirectionURI
    val authInfo = AuthInfo(user, clientId.getValue, Some(scope.toString), Some(redirectUri.toString))
    val authCode = dataHandler.getStoredAuthCode(authInfo) match {
      case Some(code) => code
      case None => dataHandler.createAuthCode(authInfo)
    }

    new AuthenticationSuccessResponse(request.getRedirectionURI, new AuthorizationCode(authCode.authorizationCode), null, null, request.getState)
  }
}

class OIDCImplicitFlow extends OIDCGrantHandler {

  override def handleRequest[U](request: AuthenticationRequest, dataHandler: OIDCDataHandler[U], user: U): AuthenticationSuccessResponse = {
    val clientId = request.getClientID
    val scope = request.getScope
    val redirectUri = request.getRedirectionURI
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

    issueAccessTokenWithIDToken(dataHandler, authInfo)
  }

  /**
   * Returns valid access token.
   *
   * @param dataHandler
   * @param authInfo
   * @return
   */
  def issueAccessTokenWithIDToken[U, H >: OIDCDataHandler[U] <: DataHandler[U]](dataHandler: H, authInfo: AuthInfo[U]): GrantHandlerResult = {
    val result = issueAccessToken(dataHandler, authInfo)
    dataHandler match {
      case handler: OIDCDataHandler[U] => {
        val idToken = handler.createIDToken(authInfo, Some(result.accessToken))
        OIDCGrantHandlerResult(
          result.tokenType,
          result.accessToken,
          result.expiresIn,
          result.refreshToken,
          None,
          idToken.serialize
        )
      }
      case _ => result
    }
  }

}
