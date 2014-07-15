package scalaoauth2.token

import play.api.libs.json.JsValue

abstract class TokenResponse[GHR] {
  def build(r: GHR): Map[String, JsValue]
}
