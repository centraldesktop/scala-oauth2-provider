package scalaoidc.provider

import org.scalatest._
import org.scalatest.Matchers._
import com.nimbusds.oauth2.sdk.{OAuth2Error, GeneralException}

class OIDCProviderSpec extends FlatSpec {

  object TestOIDCProvider extends OIDCProvider

  it should "return error message as JSON for a GeneralException" in {
    val json = TestOIDCProvider.responseOAuthErrorJson(new GeneralException("request is invalid", OAuth2Error.INVALID_REQUEST))
    (json \ "error").as[String] should be ("invalid_request")
    (json \ "error_description").as[String] should be (OAuth2Error.INVALID_REQUEST.getDescription)
  }

  it should "return error message to header for a GeneralException" in {
    val (name, value) = TestOIDCProvider.responseOAuthErrorHeader(new GeneralException("request is invalid", OAuth2Error.INVALID_REQUEST))
    name should be ("WWW-Authenticate")
    value should be ("""Bearer error="invalid_request", error_description="""" + OAuth2Error.INVALID_REQUEST.getDescription + "\"")
  }

  it should "return correct token endpoint" in {
    TestOIDCProvider.tokenEndpoint shouldBe a [OIDCTokenEndpoint]
  }
}
