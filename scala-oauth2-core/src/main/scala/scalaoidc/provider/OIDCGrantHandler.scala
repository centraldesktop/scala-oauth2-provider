package scalaoidc.provider

import scalaoauth2.provider._
import com.nimbusds.openid.connect.sdk.{AuthenticationSuccessResponse, AuthenticationRequest, AuthenticationResponse}
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
import com.nimbusds.oauth2.sdk.id.{Audience, Subject, Issuer}
import org.joda.time.{Period, DateTime}
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.RSASSASigner
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey

trait OIDCGrantHandler {
  def handleRequest[U](request: AuthenticationRequest, dataHandler: DataHandler[U]): AuthenticationResponse
}

class ImplicitFlow(clientCredentialFetcher: ClientCredentialFetcher) extends OIDCGrantHandler {

  override def handleRequest[U](request: AuthenticationRequest, dataHandler: DataHandler[U]): AuthenticationResponse = {

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
