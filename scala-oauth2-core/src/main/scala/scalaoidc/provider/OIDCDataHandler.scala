package scalaoidc.provider

import scalaoauth2.provider.{AuthInfo, DataHandler}
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import java.security.KeyPairGenerator
import com.nimbusds.jose.crypto.RSASSASigner
import java.security.interfaces.RSAPrivateKey
import org.joda.time.{Period, DateTime}
import com.nimbusds.openid.connect.sdk.claims.{AccessTokenHash, IDTokenClaimsSet}
import com.nimbusds.oauth2.sdk.id.{Audience, Subject, Issuer}
import com.nimbusds.oauth2.sdk.token.BearerAccessToken

/**
 * Auth code
 *
 * @param authorizationCode Auth code used to issue access token
 * @param redirectUri call back url to client
 * @param createdAt Auth code created date.
 * @param scope Inform the client of the scope of the auth code issued.
 * @param expiresIn Expiration date of auth code. Unit is seconds.
 */
case class AuthCode(authorizationCode: String, userId: String, redirectUri: Option[String], createdAt: Date, scope: Option[String], clientId: String, expiresIn: Option[Long])

trait OIDCDataHandler[U] extends DataHandler[U] {

  /**
   * Creates a new access token by authorized information.
   *
   * @param authInfo This value is already authorized by system.
   * @return Auth code returned to client.
   */
  def createAuthCode(authInfo: AuthInfo[U]): AuthCode

  /**
   * Returns stored auth code by authorized information.
   *
   * If want to create new auth code then have to return None
   *
   * @param authInfo This value is already authorized by system.
   * @return Auth code returned to client.
   */
  def getStoredAuthCode(authInfo: AuthInfo[U]): Option[AuthCode]

  /**
   * Deletes stored auth code for authorized information.
   *
   * @param authInfo This value is already authorized by system.
   */
  def deleteStoredAuthCodes(authInfo: AuthInfo[U])

  /**
   * A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g.,
   * 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
   *
   * @param authInfo This value is already authorized by system
   * @return Subject identifier returned with ID Token
   */
  def getSubjectIdentifier(authInfo: AuthInfo[U]): String

  /**
   * @return Issuer identifier returned with ID Token
   */
  def getIssuerIdentifier: String

  /**
   * Creates a ID Token that contains claims about the Authentication of an End-User
   * represent as a signed JSON Web Token (JWT)
   *
   * @param authInfo This value is already authorized by the system
   * @param accessToken Option access token when using Authorization Code Flow
   * @return Signed JWT returned to client.
   */
  def createIDToken(authInfo: AuthInfo[U], accessToken: Option[String]): SignedJWT = {
    val now = new DateTime
    val expiresIn = Period.hours(1)
    val idTokenClaimsSet = new IDTokenClaimsSet(
      new Issuer(getIssuerIdentifier),
      new Subject(getSubjectIdentifier(authInfo)),
      new Audience(authInfo.clientId.get).toSingleAudienceList,
      now.plus(expiresIn).toDate,
      now.toDate
    )
    accessToken match {
      case Some(token) => idTokenClaimsSet.setAccessTokenHash(AccessTokenHash.compute(new BearerAccessToken(token), JWSAlgorithm.RS256))
      case None => // Nop
    }

    val claimsSet = idTokenClaimsSet.toJWTClaimsSet
    val signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet)

    // @TODO private key should be injected into project
    val keyGenerator = KeyPairGenerator.getInstance("RSA")
    keyGenerator.initialize(1024)

    val kp = keyGenerator.genKeyPair
    val signer = new RSASSASigner(kp.getPrivate.asInstanceOf[RSAPrivateKey])

    signedJWT.sign(signer)
    signedJWT
  }
}
