package scalaoidc.provider

import com.nimbusds.openid.connect.sdk.{Nonce, AuthenticationRequest}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import org.joda.time.{Period, DateTime}
import com.nimbusds.openid.connect.sdk.claims.{AccessTokenHash, IDTokenClaimsSet}
import com.nimbusds.oauth2.sdk.id.{Audience, Subject, Issuer}
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import java.security.KeyPairGenerator
import com.nimbusds.jose.crypto.RSASSASigner
import java.security.interfaces.RSAPrivateKey
import scalaoauth2.provider.AuthorizationRequest
import com.nimbusds.oauth2.sdk.token.{BearerAccessToken, AccessToken}

class OIDCIDToken {

  def signToken(claimsSet: JWTClaimsSet): SignedJWT = {
    val signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet)

    val keyGenerator = KeyPairGenerator.getInstance("RSA")
    keyGenerator.initialize(1024)

    val kp = keyGenerator.genKeyPair

    val signer = new RSASSASigner(kp.getPrivate.asInstanceOf[RSAPrivateKey])

    signedJWT.sign(signer)
    signedJWT
  }

  def getIDToken(request: AuthenticationRequest, accessToken: Option[String]): SignedJWT = {
    val claimsSet = JWTClaimsSet(request.getClientID.toString, accessToken)
    signToken(claimsSet)
  }

  def getIDToken(request: AuthorizationRequest, accessToken: Option[String]): SignedJWT = {
    val claimsSet = JWTClaimsSet(request.clientId.get, accessToken)
    signToken(claimsSet)
  }

  def JWTClaimsSet(clientId: String, accessToken: Option[String]): JWTClaimsSet = {
    val now = new DateTime
    val expiresIn = Period.hours(1)
    val idTokenClaimsSet = new IDTokenClaimsSet(
      new Issuer("https://app.centraldesktop.com"),
      new Subject(123),
      new Audience(clientId).toSingleAudienceList,
      now.toDate,
      now.plus(expiresIn).toDate
    )
    accessToken match {
      case Some(token) => idTokenClaimsSet.setAccessTokenHash(AccessTokenHash.compute(new BearerAccessToken(token), JWSAlgorithm.RS256))
      case None => // skip
    }

    idTokenClaimsSet.toJWTClaimsSet
  }
}

object OIDCIDToken extends OIDCIDToken
