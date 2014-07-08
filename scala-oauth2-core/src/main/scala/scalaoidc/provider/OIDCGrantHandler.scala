package scalaoidc.provider

import scalaoauth2.provider._
import com.nimbusds.openid.connect.sdk.{AuthenticationSuccessResponse, AuthenticationRequest}
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import com.nimbusds.oauth2.sdk.id.{Audience, Subject, Issuer}
import org.joda.time.{Period, DateTime}
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.RSASSASigner
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import com.nimbusds.oauth2.sdk.AuthorizationCode

case class OIDCGrantHandlerResult(tokenType: String, accessToken: String, expiresIn: Option[Long], refreshToken: Option[String], scope: String, idToken: String) extends GrantHandlerResult

trait OIDCGrantHandler {
  def handleRequest[U](request: AuthenticationRequest, dataHandler: DataHandler[U]): AuthenticationSuccessResponse
}

class OIDCAuthCodeFlow extends OIDCGrantHandler {

  override def handleRequest[U](request: AuthenticationRequest, dataHandler: DataHandler[U]): AuthenticationSuccessResponse = {

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

  override def handleRequest[U](request: AuthenticationRequest, dataHandler: DataHandler[U]): AuthenticationSuccessResponse = {

    val now = new DateTime
    val expiresIn = Period.hours(1)
    val idTokenClaimsSet = new IDTokenClaimsSet(
      new Issuer("https://app.centraldesktop.com"),
      new Subject(123),
      new Audience(request.getClientID.toString).toSingleAudienceList,
      now.toDate,
      now.plus(expiresIn).toDate
    )

    idTokenClaimsSet.setNonce(request.getNonce)

    val claimsSet = idTokenClaimsSet.toJWTClaimsSet
    val signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet)

    val keyGenerator = KeyPairGenerator.getInstance("RSA")
    keyGenerator.initialize(1024)

    val kp = keyGenerator.genKeyPair

    val signer = new RSASSASigner(kp.getPrivate.asInstanceOf[RSAPrivateKey])

    signedJWT.sign(signer)

    new AuthenticationSuccessResponse(request.getRedirectionURI, null, signedJWT, null, request.getState)
  }
}

class OIDCAuthorizationCode(clientCredentialFetcher: ClientCredentialFetcher) extends GrantHandler {

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

    val authCode = dataHandler.getStoredAuthCode(authInfo).getOrElse(throw new InvalidGrant())
    val idToken = authCode.idToken.getOrElse(throw new InvalidGrant())
    val result = issueAccessToken(dataHandler, authInfo)

    OIDCGrantHandlerResult(
      result.tokenType,
      result.accessToken,
      result.expiresIn,
      result.refreshToken,
      result.scope.getOrElse(throw new InvalidGrant()),
      idToken
    )
  }

}
