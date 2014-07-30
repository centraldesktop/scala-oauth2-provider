package scalaoauth2.token

import org.scalatest._
import org.scalatest.Matchers._
import play.api.libs.json._
import scalaoauth2.provider.OAuth2GrantHandlerResult

class OAuth2AccessTokenSpec extends FlatSpec {

  it should "return token_type, access_token, expires_in, refresh_token and scope" in {
    val map = (new OAuth2AccessTokenResponse).build(OAuth2GrantHandlerResult(tokenType = "Bearer", accessToken = "access_token", expiresIn = Some(3600), refreshToken = None, scope = None))
    map.get("token_type") should contain (JsString("Bearer"))
    map.get("access_token") should contain (JsString("access_token"))
    map.get("expires_in") should contain (JsNumber(3600))
    map.get("refresh_token") should be (None)
    map.get("scope") should be (None)
    map.get("id_token") should be (None)
  }
}
