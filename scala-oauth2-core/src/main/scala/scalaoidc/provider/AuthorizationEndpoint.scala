package scalaoidc.provider

import scalaoauth2.provider._
import com.nimbusds.openid.connect.sdk.{AuthenticationResponse, AuthenticationRequest}

class AuthorizationEndpoint {
  val fetcher = ClientCredentialFetcher

  val handlers = Map(
    "id_token" -> new ImplicitFlow(fetcher)
  )

  def handleRequest[U](request: AuthenticationRequest, dataHandler: DataHandler[U]): Either[OAuthError, AuthenticationResponse] = try {
    val responseType = request.getResponseType
    val handler = handlers.get(responseType.toString).getOrElse(throw new UnsupportedResponseType("the response_type isn't supported"))

    Right(handler.handleRequest(request, dataHandler))
  } catch {
    case e: OAuthError => Left(e)
  }
}

object AuthorizationEndpoint extends AuthorizationEndpoint
