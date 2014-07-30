package scalaoauth2.token

import play.api.libs.json.{JsNumber, JsString, JsValue}
import scalaoauth2.provider.GrantHandlerResult

class OAuth2AccessTokenResponse[GHR <: GrantHandlerResult] extends TokenResponse[GHR] {
  def build(r: GHR): Map[String, JsValue] = {
    Map[String, JsValue](
      "token_type" -> JsString(r.tokenType),
      "access_token" -> JsString(r.accessToken)
    ) ++ r.expiresIn.map {
      "expires_in" -> JsNumber(_)
    } ++ r.refreshToken.map {
      "refresh_token" -> JsString(_)
    } ++ r.scope.map {
      "scope" -> JsString(_)
    }
  }
}