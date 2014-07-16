package scalaoidc.token

import org.scalatest._
import org.scalatest.Matchers._
import play.api.libs.json._
import scalaoauth2.token.OAuth2AccessTokenResponse
import scalaoidc.provider.OIDCGrantHandlerResult

class OIDCIDTokenSpec extends FlatSpec {

  it should "mixin id_token" in {
    val result = OIDCGrantHandlerResult(tokenType = "Bearer", accessToken = "access_token", expiresIn = Some(3600), refreshToken = None, scope = None, idToken = "id_token")
    val map = (new OAuth2AccessTokenResponse).build(result)

    map.get("token_type") should contain (JsString("Bearer"))
    map.get("access_token") should contain (JsString("access_token"))
    map.get("expires_in") should contain (JsNumber(3600))
    map.get("refresh_token") should be (None)
    map.get("scope") should be (None)
    map.get("id_token") should be (None)

    val mapWithToken = new OAuth2AccessTokenResponse[OIDCGrantHandlerResult] with OIDCIDToken[OIDCGrantHandlerResult]
      .build(result)

    mapWithToken.get("token_type") should contain (JsString("Bearer"))
    mapWithToken.get("access_token") should contain (JsString("access_token"))
    mapWithToken.get("expires_in") should contain (JsNumber(3600))
    mapWithToken.get("refresh_token") should be (None)
    mapWithToken.get("scope") should be (None)
    mapWithToken.get("id_token") should contain (JsString("id_token"))
  }
}
