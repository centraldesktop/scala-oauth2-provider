package scalaoidc.token

import scalaoauth2.token._
import scalaoidc.provider.OIDCGrantHandlerResult
import play.api.libs.json.JsString

trait OIDCIDToken[GHR <: OIDCGrantHandlerResult] extends TokenResponse[GHR] {
  abstract override def build(r: GHR) = {
    super.build(r) + (
      "id_token" -> JsString(r.idToken)
    )
  }
}
