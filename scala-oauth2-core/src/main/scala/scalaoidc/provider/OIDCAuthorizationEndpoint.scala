package scalaoidc.provider

import scalaoauth2.provider._
import com.nimbusds.openid.connect.sdk.{AuthenticationSuccessResponse, AuthenticationRequest}
import com.nimbusds.oauth2.sdk.{OAuth2Error, ParseException}

class OIDCAuthorizationEndpoint {

  val handlers = Map(
    "code" -> new OIDCAuthCodeFlow,
    "id_token" -> new OIDCImplicitFlow
  )

  def handleRequest[U](request: AuthenticationRequest, dataHandler: DataHandler[U]): AuthenticationSuccessResponse = {
    val responseType = request.getResponseType
    val handler = handlers.get(responseType.toString).getOrElse(
      throw new ParseException("the response_type isn't supported",
        OAuth2Error.UNSUPPORTED_RESPONSE_TYPE,
        request.getClientID, request.getRedirectionURI, request.getState)
    )

    handler.handleRequest(request, dataHandler)
  }
}

object OIDCAuthorizationEndpoint extends OIDCAuthorizationEndpoint
