package scalaoidc.provider

import scalaoauth2.provider._

class OIDCTokenEndpoint extends TokenEndpoint {
  override val handlers = super.handlers.updated("authorization_code", new OIDCAuthorizationCode(super.fetcher))
}

object OIDCTokenEndpoint extends OIDCTokenEndpoint
